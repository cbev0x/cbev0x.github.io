---
title: "AD CS Abuse Research"
date: 2026-06-04
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

## PKI Internals, Certificate Enrollment, and Weak Mapping Exploitation (ESC9 / ESC10)

---

## Table of Contents

1. [What AD CS Actually Is](#1-what-ad-cs-actually-is)
2. [The PKI Trust Model in Active Directory](#2-the-pki-trust-model-in-active-directory)
3. [Where Everything Lives: The Configuration Partition](#3-where-everything-lives-the-configuration-partition)
4. [Certificate Templates: The Attributes That Matter](#4-certificate-templates-the-attributes-that-matter)
5. [The Enrollment Flow End to End](#5-the-enrollment-flow-end-to-end)
6. [PKINIT: Certificate to TGT](#6-pkinit-certificate-to-tgt)
7. [Strong vs Weak Certificate Mapping (KB5014754)](#7-strong-vs-weak-certificate-mapping-kb5014754)
8. [The ESC Taxonomy: A Map of the Attack Surface](#8-the-esc-taxonomy-a-map-of-the-attack-surface)
9. [ESC9: CT_FLAG_NO_SECURITY_EXTENSION](#9-esc9-ct_flag_no_security_extension)
10. [ESC10: Weak Certificate Mapping via Registry](#10-esc10-weak-certificate-mapping-via-registry)
11. [OPSEC Profile: ESC9 and ESC10](#11-opsec-profile-esc9-and-esc10)
12. [Detection and Defensive Indicators](#12-detection-and-defensive-indicators)

---

## 1. What AD CS Actually Is

Active Directory Certificate Services is Microsoft's implementation of a Public Key Infrastructure baked directly into Active Directory. The concept of a PKI is not Microsoft-specific — it is the broader framework of using asymmetric cryptography to establish trust between parties who have never directly negotiated a secret. A Certificate Authority sits at the centre of that framework: it is a trusted third party that signs certificates binding a public key to an identity, and anyone who trusts the CA can trust those bindings.

What makes AD CS distinct from a generic PKI deployment is that it reuses Active Directory's existing identity store rather than maintaining its own. The CA does not have its own user database — when it needs to know who someone is, it queries AD. When it needs to know what a principal is allowed to request, it reads ACLs on AD objects. When it issues a certificate, the identity embedded in that certificate is sourced from AD attributes. This tight coupling is what makes AD CS misconfigurations so severe: a flaw in the PKI layer translates directly into domain authentication compromise because certificates are accepted as first-class credentials by Kerberos.

Certificates issued by an enterprise CA are used throughout AD environments for:

- **Kerberos authentication** via PKINIT — a certificate with the right EKU can be exchanged for a TGT without a password
- **LDAPS / TLS** — securing LDAP over TLS using domain controller certificates
- **Smart card logon** — hardware-backed authentication using cert-bound keys
- **Code signing, email encryption, EFS** — various application-layer PKI uses

Of these, PKINIT is the primary attack path. It is the mechanism by which a certificate becomes a Kerberos credential, and it is what every ESC ultimately targets.

---

## 2. The PKI Trust Model in Active Directory

The trust chain in an AD CS deployment has three layers:

**The Root CA** is the ultimate trust anchor. Its certificate is self-signed and distributed to every machine in the domain via Group Policy, landing in the `Trusted Root Certification Authorities` store. Trusting the root CA means trusting every certificate it signs, directly or transitively.

**The Issuing (Enterprise) CA** is the CA that actually handles enrollment requests from domain members. In most environments this is the same machine as the root CA (a combined root/issuing CA), though larger deployments separate them. The issuing CA's certificate is signed by the root CA and is distributed to the `Intermediate Certification Authorities` store domain-wide. All certificates issued to users and computers are signed by the issuing CA's private key.

**Issued certificates** are the leaf nodes — the actual certs held by users, computers, and services. Their validity depends entirely on the chain back to the trusted root.

The critical security property of this model: **trusting the CA means trusting every certificate it issues, for the lifetime of those certificates.** A compromised or misconfigured CA does not just compromise one credential — it compromises the authentication fabric of the entire domain. An attacker who can obtain a certificate naming a Domain Admin from a trusted CA has a persistent credential that survives password resets, account lockouts, and in many cases even account deletion (until certificate revocation is enforced).

### Why Certificate Auth is Powerful for Attackers

Password-based Kerberos authentication is ephemeral from an attacker's perspective — a password change kills the TGT, and the new TGT requires the new password. Certificate-based authentication via PKINIT is different: the credential is the certificate itself, signed by the CA, valid for the certificate's entire validity period (commonly one to two years for user templates). A password reset does not revoke a certificate. The certificate's binding is to an identity (the UPN or SAN embedded at issuance time), not to a secret the victim controls.

This is why ESC exploitation is so impactful relative to effort: a single certificate request, if the template is misconfigured, yields a multi-year authentication credential for any principal the attacker names.

---

## 3. Where Everything Lives: The Configuration Partition

All AD CS configuration is stored in the Active Directory Configuration partition, which is replicated domain-wide and readable by all authenticated users by default. This is enumerable without elevated privileges using standard LDAP queries — which is why Certipy's `find` command works with any domain account.

The base path is:

```
CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com
```

The key containers under this path:

**`CN=Certificate Templates`** — one AD object per template. This is where template configuration lives: which EKUs are included, what subject/SAN flags are set, what enrollment permissions are granted, and how many RA signatures are required. The `nTSecurityDescriptor` on each template object controls who can enroll and who has write access.

**`CN=Enrollment Services`** — one AD object per enterprise CA. Each object lists the templates published on that CA (`certificateTemplates` attribute) and carries the CA-level configuration flags that override template behaviour.

**`CN=NTAuthCertificates`** — a single object whose `cACertificate` attribute contains the certificates of every CA trusted for PKINIT and smart card logon. A CA must appear here for certificates it issues to be accepted by domain controllers for Kerberos authentication. This is the object targeted by the Golden Certificate technique — adding a rogue CA certificate here makes the KDC trust forged certificates from an attacker-controlled CA.

**`CN=AIA`** and **`CN=CDP`** — Authority Information Access and CRL Distribution Points. These define where clients fetch the CA certificate chain and certificate revocation lists. Relevant for OPSEC: CRL fetches can generate network noise when certificates are validated.

---

## 4. Certificate Templates: The Attributes That Matter

A certificate template is an AD object that acts as a policy specification — it tells the CA what kind of certificate to issue, to whom, and with what content. Understanding the key LDAP attributes is essential for both exploitation and for building tooling that correctly identifies vulnerable conditions.

### `mspki-certificate-name-flag`

This integer attribute is a bitmask controlling how the certificate's Subject and Subject Alternative Name fields are populated.

The flag that matters most for exploitation is `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x00000001`). When this bit is set, the CA accepts the Subject Distinguished Name and SAN directly from the submitted CSR rather than building them from the requester's AD attributes. The CA does not validate that the requester is entitled to the identity they are claiming in the CSR — it simply embeds whatever was in the request. This is the root condition for ESC1: combined with an auth-enabling EKU and low-privilege enrollment rights, it allows any enrollee to obtain a certificate naming an arbitrary principal.

A second relevant flag is `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (`0x00000400`). When set, the CA constructs the SAN UPN from the requester's AD `userPrincipalName` — meaning the identity in the cert is always the actual requester. This flag's absence (when `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is also absent) leaves SAN construction to the CA's default behaviour, which is to build it from AD.

### `mspki-enrollment-flag`

Another bitmask, controlling enrollment behaviour rather than subject construction.

`CT_FLAG_NO_SECURITY_EXTENSION` (`0x00080000`) is the flag directly relevant to ESC9. When set, the CA does not embed the `szOID_NTDS_CA_SECURITY_EXT` OID (`1.3.6.1.4.1.311.25.2`) extension in issued certificates. This extension, introduced with KB5014754, carries the `objectSid` of the AD account the CA looked up at issuance time. Domain controllers in enforcement mode require this extension and cross-validate the SID it contains against the account whose UPN appears in the SAN. Suppressing the extension downgrades authentication to weak mapping — UPN-only, with no SID validation.

`CT_FLAG_PEND_ALL_REQUESTS` (`0x00000002`) is worth noting for OPSEC: when set, all requests go to a pending queue requiring CA manager approval before issuance. Templates without this flag issue immediately, which is the norm for exploitable templates.

### `pKIExtendedKeyUsage`

A multi-valued attribute containing the EKU OIDs the CA will embed in issued certificates. For PKINIT to succeed, the certificate needs at least one of:

- `1.3.6.1.5.5.7.3.2` — Client Authentication
- `1.3.6.1.4.1.311.20.2.2` — Smart Card Logon
- `1.3.6.1.5.2.3.4` — PKINIT Client Auth (less common)
- `2.5.29.37.0` — Any Purpose (ESC2: accepts any use including authentication)

A certificate with no EKU at all is also usable for authentication in some configurations — absence of EKU constraints means the certificate is valid for all purposes.

The `Certificate Request Agent` OID (`1.3.6.1.4.1.311.20.2.1`) is the enrollment agent EKU. A certificate bearing this OID can be used to request certificates *on behalf of other principals* — the mechanism behind ESC3.

### `mspki-ra-signature`

An integer specifying how many Registration Authority (enrollment agent) counter-signatures are required on a CSR before the CA will issue against this template. A value of `0` means no counter-signature is required — the CSR can be submitted directly. For ESC3 to be exploitable, this must be `0` on the target template (the one being enrolled via the enrollment agent).

### `nTSecurityDescriptor`

The access control list on the template object. Two distinct sets of rights matter:

**Enrollment rights** — the `Certificate-Enrollment` extended right (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) allows a principal to request a certificate from this template. When `Authenticated Users`, `Domain Users`, or `Domain Computers` holds Allow on this right, the template is low-privilege enrollable.

**Write rights** — `WriteProperty`, `WriteDacl`, `WriteOwner`, and `GenericWrite` on the template object allow modifying the template's configuration attributes. This is the ESC4 condition: write access to a template allows an attacker to set `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and an auth EKU, converting the template into an ESC1-exploitable state.

### CA-Level: `EDITF_ATTRIBUTESUBJECTALTNAME2`

This flag lives on the CA object in `CN=Enrollment Services`, not on individual templates. When set (value `0x40` in the CA's policy edit flags), it instructs the CA to accept SAN values from the CSR on *any* template, regardless of that template's individual `mspki-certificate-name-flag` settings. It is set via `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA server and constitutes ESC6. Detecting it requires reading the CA object's attributes, not just the template objects.

---

## 5. The Enrollment Flow End to End

Understanding exactly what happens during a certificate request — and which party controls what — is the foundation for understanding why each ESC works.

### Step 1: Key pair generation

The client generates an RSA or ECC key pair locally. The private key never leaves the client (in normal operation). The public key will be embedded in the CSR and ultimately in the issued certificate, binding the cert to this specific key material.

### Step 2: CSR construction (PKCS#10)

The client constructs a Certificate Signing Request — a PKCS#10 structure containing:

- The public key
- The requested Subject Distinguished Name (e.g., `CN=User,DC=domain,DC=com`)
- Any requested extensions, including a proposed SAN if the template permits it
- A signature over the CSR using the private key — this proves the requester possesses the private key corresponding to the submitted public key

The Subject and SAN values in the CSR are *requests*, not guarantees. Whether the CA honours them, overrides them, or rejects them depends entirely on the template's `mspki-certificate-name-flag` and the CA-level `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

### Step 3: LDAP template lookup

Before submitting, the client reads the target template's attributes from `CN=Certificate Templates` via LDAP to confirm the template is published on an accessible CA and to determine what the request should look like.

### Step 4: Transport authentication and CSR submission

The client authenticates to the CA and submits the CSR. The transport and interface determine how authentication occurs:

- **MS-WCCE over named pipe (`\pipe\cert`)** — authentication is handled by the SMB session over port 445. The CA's policy module receives the request and calls `GetSecurityContext()` to identify the requester — it sees the SMB session's authenticated identity. NTLM or Kerberos, depending on what the client negotiated.
- **MS-ICPR over named pipe (`\pipe\ICertPassage`) or TCP** — the older RPC interface. Same auth model but a different binding. This is the ESC11 target.
- **HTTP enrollment (`/certsrv`)** — authentication via HTTP NTLM or Kerberos. This endpoint does not require HTTPS by default and is the ESC8 relay target.

The template name is passed as part of the request attributes, not inside the CSR itself.

### Step 5: CA permission checks

The CA performs two sequential permission checks:

First, it checks its own enrollment permissions — the `nTSecurityDescriptor` on the CA object in `CN=Enrollment Services`. The authenticated identity must have `Certificate-Enrollment` allow on the CA object. This check is almost universally passed in domain environments because CAs are typically configured to allow `Authenticated Users` to enroll.

Second, it checks the template's enrollment permissions — the `nTSecurityDescriptor` on the specific template object in `CN=Certificate Templates`. Again, `Certificate-Enrollment` allow on the requester's identity (or a group it belongs to) is required.

Both checks use the **transport-layer security context** — whoever authenticated at the SMB or HTTP layer. This is why NTLM relay attacks work: the relayed identity passes both permission checks, and the CSR content (including any attacker-controlled SAN) is processed under that identity's context.

### Step 6: Template policy validation

The CA policy module processes the CSR against the template's configuration:

- Verifies the request signature (proof of private key possession)
- Checks whether the template requires manager approval (`CT_FLAG_PEND_ALL_REQUESTS`)
- Checks whether an RA counter-signature is required (`mspki-ra-signature`)
- Evaluates the requested Subject and SAN against `mspki-certificate-name-flag` — determines whether to use values from the CSR or build from AD
- Validates or overrides the requested EKU against `pKIExtendedKeyUsage`

### Step 7: Certificate construction

If all checks pass, the CA builds the certificate. For the Subject and SAN:

- If `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set — values are taken from the CSR as submitted
- If not — the CA queries AD using the requester's identity and builds the Subject from the account's `distinguishedName` and the SAN UPN from `userPrincipalName`

The CA then adds extensions. Critically, unless `CT_FLAG_NO_SECURITY_EXTENSION` is set on the template, it embeds `szOID_NTDS_CA_SECURITY_EXT` — containing the `objectSid` of the AD account it looked up for the requester. This extension is what strong certificate mapping depends on.

The CA signs the constructed certificate with its own private key and returns it as a PKCS#7 response.

### Step 8: Certificate storage

The client receives and stores the certificate alongside the corresponding private key, typically as a PFX (PKCS#12) bundle for portability or in the Windows certificate store for native tooling.

---

## 6. PKINIT: Certificate to TGT

PKINIT (RFC 4556) is the Kerberos extension that allows a certificate to serve as the preauthentication credential in an AS exchange. It is the bridge between the PKI layer and the Kerberos authentication layer.

### The AS-REQ with PA-PK-AS-REQ

Instead of the standard encrypted timestamp preauthentication, the client sends a `PA-PK-AS-REQ` structure containing:

- A CMS (Cryptographic Message Syntax) `SignedData` blob containing the client's certificate and the AS request body, signed with the client's private key
- The full certificate chain up to a CA trusted by the KDC

The client's signature over the AS request body serves the same purpose as knowing the password in standard Kerberos — it proves the client possesses the private key bound to the certificate.

### KDC Validation

The KDC (running on the DC) processes the `PA-PK-AS-REQ` by:

1. Validating the certificate chain up to a CA in `CN=NTAuthCertificates`
2. Verifying the EKU — the cert must have Client Authentication, Smart Card Logon, or equivalent
3. Checking certificate revocation (CRL or OCSP) if configured — often not enforced in practice
4. Mapping the certificate to an AD account (detailed in the next section)
5. Constructing the PAC for the mapped account and issuing the TGT

### Certificate-to-Account Mapping

This step is where the attack surface lives. The KDC must determine *which AD account* the certificate represents. There are two mechanisms:

**Strong mapping** uses the `szOID_NTDS_CA_SECURITY_EXT` extension embedded in the certificate. The KDC extracts the `objectSid` from this extension and looks up the account with that SID directly. The UPN in the SAN is also verified to match that account. Because the SID in the extension was written by the CA at issuance time based on the *actual requester's* AD account, a certificate with a manipulated UPN but a legitimate requester's SID will fail strong mapping — the SID and UPN point to different accounts.

**Weak mapping** falls back to UPN-only lookup. The KDC extracts the UPN from the SAN, queries AD for `userPrincipalName` matching that value, and issues a TGT for whatever account it finds. There is no cross-validation with a SID. A certificate with `administrator@domain.com` in the SAN UPN will map to the Administrator account regardless of who originally requested the certificate.

This mapping asymmetry is the root cause of ESC9 and ESC10.

### UnPAC-the-Hash

A PKINIT quirk worth noting: the AS-REP in a PKINIT exchange encrypts the session key using the client's public key (Diffie-Hellman key agreement, specifically). Because the session key is not derived from the account's NT hash, the AS-REP does not contain material that can be used to recover the NT hash — *except* via a specific technique. The KDC also encrypts the session key under the account's NT hash in the `enc-pa-data` field for compatibility. Requesting the session key via `U2U` (User-to-User) allows recovering the NT hash from the PKINIT exchange, which is what tools like Certipy's `auth -pfx` do when they print the NT hash alongside the TGT. This is useful because the hash can be passed directly for lateral movement without needing a PKINIT-capable service.

---

## 7. Strong vs Weak Certificate Mapping (KB5014754)

KB5014754 is the Microsoft patch that introduced strong certificate mapping for PKINIT. Understanding its three enforcement phases is essential for knowing when ESC9 and ESC10 apply.

### Background: The Problem KB5014754 Addressed

Before KB5014754, the KDC always used weak mapping — UPN-only lookup with no SID validation. This made ESC9-style attacks trivially possible on any domain regardless of template configuration, because any cert with any UPN in the SAN would be accepted. The patch introduced the `szOID_NTDS_CA_SECURITY_EXT` mechanism and changed the KDC's mapping behaviour based on a registry key and the presence of the extension in the presented certificate.

### The Three Modes

**Disabled (pre-patch or registry override)** — weak mapping always used. The KDC ignores `szOID_NTDS_CA_SECURITY_EXT` entirely even if present. ESC9 conditions are irrelevant because every certificate uses weak mapping.

**Compatibility mode (default after patch, before enforcement date)** — the KDC prefers strong mapping when the `szOID_NTDS_CA_SECURITY_EXT` extension is present and valid. If the extension is absent, the KDC falls back to weak mapping and logs a warning event (Event ID 39 on the DC). This is the mode where ESC9 applies: suppressing the extension forces the fallback to weak UPN mapping.

**Enforcement mode (enabled via registry or after Microsoft's enforcement deadline)** — the KDC requires the `szOID_NTDS_CA_SECURITY_EXT` extension. Certificates lacking it are rejected outright for PKINIT. In this mode, ESC9 no longer works for authentication — the cert will be issued but the KDC will refuse it.

The registry key controlling this on domain controllers is:

```
HKLM\SYSTEM\CurrentControlSet\Services\Kdc
Value: StrongCertificateBindingEnforcement
0 = Disabled (weak mapping always)
1 = Compatibility mode (default)
2 = Full enforcement
```

Enumerating this value on DCs is a prerequisite check for ESC9 exploitability. It is not readable via standard LDAP — it requires registry access to the DC, which typically means either local admin on the DC or a remote registry read via SMB if the `RemoteRegistry` service is running and accessible.

### What the `szOID_NTDS_CA_SECURITY_EXT` Extension Contains

The extension value is a DER-encoded structure containing the `objectSid` of the AD principal the CA associated with the certificate at issuance time. The CA populates this by looking up the authenticated requester's account in AD — it is not taken from the CSR, it is not attacker-controlled in a normal ESC9 scenario.

In enforcement mode, the KDC:
1. Extracts the UPN from the SAN and finds the corresponding AD account
2. Extracts the SID from `szOID_NTDS_CA_SECURITY_EXT`
3. Validates that the SID in the extension matches the `objectSid` of the account found in step 1
4. Rejects if they do not match

A certificate with `administrator@domain.com` in the SAN UPN and the attacker's account SID in the extension will fail step 3 in enforcement mode — the SID maps to the attacker's account, not Administrator.

---

## 8. The ESC Taxonomy: A Map of the Attack Surface

The ESC numbering (ESC1 through ESC15+) originated in the SpecterOps whitepaper "Certified Pre-Owned" and has been extended by subsequent research. Each ESC identifies a distinct misconfiguration class, though many chains involve multiple ESCs.

A useful mental model groups them by what layer they attack:

**Template misconfiguration (ESC1–4, ESC9)** — flaws in how an individual template is configured. Exploitable by any principal with enrollment rights on that template.

**CA misconfiguration (ESC6, ESC7, ESC8, ESC11)** — flaws in how the CA itself is configured or secured. Often higher impact because they affect all templates published on that CA.

**Certificate mapping bypass (ESC9, ESC10)** — attacks that exploit weak certificate-to-account mapping at the KDC level rather than manipulating what the CA issues.

**AD object write (ESC4, ESC5, ESC7, ESC14, ESC15)** — attacks that begin with write access to an AD or CA object and modify configuration to enable a certificate-based authentication path.

The distinction between "CA trusts wrong identity" (ESC1–4, ESC6–8) and "KDC maps cert to wrong account" (ESC9–10) is important for tooling and OPSEC: the former generates CA audit events at the issuance stage, while the latter generates KDC events at the authentication stage, with the issuance appearing entirely normal.

---

## 9. ESC9: CT_FLAG_NO_SECURITY_EXTENSION

### Vulnerability Class

ESC9 is a certificate mapping bypass. Unlike ESC1, the template does not need to allow enrollee-supplied SANs — the certificate the attacker obtains will contain their own identity in the SAN. The attack works by forcing the KDC onto the weak UPN-only mapping path, then exploiting a mismatch between the UPN embedded in the cert (which was sourced from the attacker's or victim's AD account at issuance time) and the current state of that UPN in AD.

### Prerequisites

All of the following conditions must hold:

1. A certificate template has `CT_FLAG_NO_SECURITY_EXTENSION` (`0x00080000`) set in `mspki-enrollment-flag`
2. The template has an auth-enabling EKU (Client Authentication, Smart Card Logon, or Any Purpose)
3. The template is enrollable by a low-privilege principal (or by a principal the attacker controls)
4. The attacker has `GenericWrite` (or equivalent) over another AD user or computer account — specifically the ability to modify the `userPrincipalName` attribute of that account
5. The DC is in compatibility mode (not full enforcement) for certificate mapping — `StrongCertificateBindingEnforcement` is `0` or `1`

Condition 4 is what makes this different from ESC1. The attacker does not forge an arbitrary SAN — they temporarily modify a victim account's UPN to match a high-privilege target's UPN, enroll a certificate against the ESC9-vulnerable template (obtaining a cert with the manipulated UPN embedded), restore the original UPN, then use the cert (which now has the high-privilege UPN but the attacker's or victim's SID in the absent extension) for PKINIT.

### Attack Chain

**Step 1: Identify the target and the ESC9 template**

Enumerate certificate templates for `CT_FLAG_NO_SECURITY_EXTENSION` in `mspki-enrollment-flag` combined with an auth EKU and enrollment rights accessible to the attacker.

```
mspki-enrollment-flag & 0x00080000 == 0x00080000
```

**Step 2: Obtain GenericWrite over a victim account**

This is a lateral prerequisite — ESC9 does not give you GenericWrite, it requires it. Common sources: ACL misconfigurations found via BloodHound, WriteProperty on specific attributes delegated to a group the attacker is in, or an account the attacker already controls.

The `userPrincipalName` attribute is what matters. `GenericWrite` over an object grants write access to all non-protected attributes including `userPrincipalName`. Alternatively, if the attacker controls their own account, they can modify their own UPN directly (standard users can write their own `userPrincipalName` in many domain configurations).

**Step 3: Modify the victim account's UPN to match the target**

Change the victim account's `userPrincipalName` from its legitimate value to the UPN of the account being impersonated (e.g., `administrator@domain.com`).

```bash
# Certipy
certipy account update -u attacker@domain.com -p Password1 \
  -user victimuser -upn administrator@domain.com

# Impacket / ldap3 equivalent
# Modify userPrincipalName attribute via LDAP modify operation
```

**Step 4: Enroll a certificate from the ESC9 template as the victim account**

Request a certificate from the vulnerable template. Because `CT_FLAG_NO_SECURITY_EXTENSION` is set, the issued cert will not contain `szOID_NTDS_CA_SECURITY_EXT`. Because the victim account's UPN is now `administrator@domain.com`, the CA builds the SAN UPN from that value — the cert will have `administrator@domain.com` in the SAN.

```bash
certipy req -u victimuser@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'VulnerableTemplate' \
  -dc-ip 10.10.10.10
```

**Step 5: Restore the victim account's UPN**

Change `userPrincipalName` back to its original value before the modification is noticed or breaks other authentication. The issued certificate retains the `administrator@domain.com` UPN — changing the account's UPN back does not affect already-issued certificates.

```bash
certipy account update -u attacker@domain.com -p Password1 \
  -user victimuser -upn victimuser@domain.com
```

**Step 6: Authenticate using the certificate**

Submit the certificate for PKINIT. The KDC in compatibility mode sees `administrator@domain.com` in the SAN, looks up that UPN in AD, finds the Administrator account, checks for `szOID_NTDS_CA_SECURITY_EXT` — it is absent — logs a warning in compatibility mode (or silently accepts in disabled mode) and issues a TGT for Administrator.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### Why the SID Cross-check Fails to Catch This

The reason strong mapping breaks this attack is instructive: if `szOID_NTDS_CA_SECURITY_EXT` were present, it would contain the `objectSid` of whoever the CA looked up when it built the cert. In step 4, the CA looked up the victim account (because the attacker enrolled as the victim) — so the extension would contain the *victim's* SID, not Administrator's SID. When the KDC tried to validate `administrator@domain.com` UPN against the victim's SID, the check would fail. The `CT_FLAG_NO_SECURITY_EXTENSION` flag prevents the extension from being written at all, forcing the KDC onto the UPN-only path where no such cross-check is performed.

### Variant: Attacker Controls Their Own Account

If the attacker controls a regular domain account and can write their own `userPrincipalName`, the attack simplifies: no need for GenericWrite over a victim. Modify own UPN to target's UPN, enroll on ESC9 template as self, restore UPN, authenticate. The enrolled cert's SAN will reflect whatever the UPN was at enrollment time.

---

## 10. ESC10: Weak Certificate Mapping via Registry

### Vulnerability Class

ESC10 is similar in outcome to ESC9 — it exploits weak UPN-based certificate mapping — but the enablement condition is different. Rather than requiring a template flag that suppresses the security extension, ESC10 applies when the KDC has been explicitly configured to use weak mapping via the `StrongCertificateBindingEnforcement` registry key.

The SpecterOps research identifies two distinct ESC10 sub-cases, which are worth treating separately.

### ESC10 Case 1: KDC Weak Mapping with GenericWrite

**Prerequisite**: `StrongCertificateBindingEnforcement` on the DC(s) is set to `0` (disabled). In this state, the KDC always uses weak mapping regardless of whether certificates contain `szOID_NTDS_CA_SECURITY_EXT`. The extension is ignored completely.

The attack flow is nearly identical to ESC9 but requires no vulnerable template flag — *any* template with an auth EKU that builds the SAN from AD is usable. Because the KDC never checks the security extension, every certificate becomes a potential ESC9-equivalent.

**Prerequisites**:

1. `StrongCertificateBindingEnforcement = 0` on the DC (registry key, not readable via standard LDAP)
2. Any enrollable template with auth EKU that builds SAN from AD (no `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` needed)
3. `GenericWrite` over a target account to modify `userPrincipalName`

**Attack chain**: identical to ESC9 — modify victim UPN, enroll cert (any suitable template), restore UPN, authenticate.

### ESC10 Case 2: KDC Weak Mapping without GenericWrite

**Prerequisite**: `StrongCertificateBindingEnforcement` is `0` AND `CertificateMappingMethods` on the DC includes the UPN mapping method (`0x4`).

This case is more interesting because it does not require write access to any account's UPN. It instead targets machine accounts and the `userPrincipalName` behaviour difference between user and computer objects.

Machine account objects (`CN=Computer,...`) do not have a `userPrincipalName` attribute by default — their Kerberos identity is based on `dNSHostName` and `sAMAccountName`. However, if a computer account is enrolled in a template that builds the SAN UPN from AD, the resulting UPN in the cert will be the `userPrincipalName` value if present, or fall back to a constructed value.

The specific chain here: if the attacker has write access to a computer account's `dNSHostName` attribute (which may be writable by the computer account itself or by accounts with delegated rights), they can set it to match a domain controller's hostname, enroll a cert in a machine-cert template, and obtain a cert that the KDC maps to the DC's machine account in weak mapping mode — enabling DCSync via pass-the-cert.

This chain is less commonly exploitable but represents the "no GenericWrite on user accounts" variant of the weak mapping attack class.

### Distinguishing ESC9 from ESC10

| Condition | ESC9 | ESC10 Case 1 | ESC10 Case 2 |
|---|---|---|---|
| Requires vulnerable template flag | Yes (`CT_FLAG_NO_SECURITY_EXTENSION`) | No | No |
| Requires KDC weak mapping registry | Compatibility or disabled | Disabled (`0`) | Disabled (`0`) |
| Requires GenericWrite on user | Yes | Yes | No (needs computer attribute write) |
| Works in full enforcement mode | No | No | No |
| Template type needed | Any auth EKU with ESC9 flag | Any auth EKU | Machine cert template |

---

## 11. OPSEC Profile: ESC9 and ESC10

ESC9 and ESC10 generate a distinct log pattern compared to ESC1-style attacks because the certificate issuance looks entirely legitimate — the cert contains the attacker-controlled account's (or victim account's) identity, issued from a valid template with no anomalous SAN. The suspicious activity appears in AD object modification events and KDC authentication events, not in CA audit logs.

### CA-Side Events

**Event ID 4886 — Certificate Issued**: Generated on the CA for every issued certificate. In ESC9/ESC10, this event will show a completely normal certificate issuance — the template name, the requester's identity, and the issued cert's subject will all appear legitimate. Unlike ESC1, there is no suspicious SAN present that would stand out. The only indicator is the template name; if the template has `CT_FLAG_NO_SECURITY_EXTENSION` set, a defender with deep template knowledge might flag certs from it as higher risk, but this requires custom detection logic.

CA audit logging must be enabled to see 4886 at all. Check with:
```
certutil -getreg CA\AuditFilter
```
A value of `0` means no auditing. `127` enables all audit events.

### DC-Side Events (KDC)

**Event ID 39 (Kerberos-Key-Distribution-Center)**: Generated when the KDC accepts a PKINIT authentication using weak mapping (certificate lacks `szOID_NTDS_CA_SECURITY_EXT` in compatibility mode). This is the most reliable detection indicator for ESC9. It explicitly logs the account name and certificate details. Defenders who monitor this event will catch ESC9 authentications in compatibility mode.

**Event ID 40**: Generated when a certificate is rejected due to mapping failure in enforcement mode. Seeing 40s after deploying enforcement is normal initially; sustained 40s are a sign of active exploitation attempts or legitimate certificates that need re-issuance.

**Event ID 4768 — Kerberos TGT Request**: Standard TGT issuance event. For PKINIT authentications, the `Pre-Authentication Type` field will be `17` (PKINIT with DH) or `16` (PKINIT with RSA). Baseline what normal PKINIT looks like in the environment — service accounts and workstations using cert auth will generate these. Anomalies are unusual accounts suddenly using PKINIT, particularly privileged accounts.

### AD Object Modification Events (Domain Controller Security Log)

**Event ID 4738 — User Account Changed**: Generated when `userPrincipalName` is modified. ESC9 requires changing a UPN, which generates this event with the old and new UPN values visible in the event data. In a normal environment, UPN changes are rare. Two 4738 events in quick succession on the same account (change to target UPN, then change back) is a near-certain ESC9 indicator.

**Event ID 4742 — Computer Account Changed**: Same as 4738 but for computer objects. Relevant for ESC10 Case 2 chains involving `dNSHostName` modification.

### Noise Profile

| Activity | Events Generated | Baseline Frequency | Anomaly Threshold |
|---|---|---|---|
| UPN modification | 4738 on DC | Very rare in most environments | Any unexpected change |
| Certificate issuance | 4886 on CA | Moderate — normal enrollment | Template-specific |
| PKINIT authentication | 4768 (PreAuth=17) on DC | Low-moderate | Privileged accounts using PKINIT |
| Weak mapping fallback | Event ID 39 on DC | Should be zero post-KB5014754 | Any occurrence |
| UPN restoration | 4738 on DC | Very rare | Paired with prior 4738 |

### OPSEC Hardening for Operators

The UPN modification is the noisiest step. Mitigations:

**Use accounts you already control** rather than modifying a victim's UPN. If the attacker's own account can enroll on the ESC9 template, and the attacker can write their own UPN (test this — it is sometimes permitted), the only 4738 event generated is for the attacker's own account. This is less suspicious than modifying another account's UPN.

**Time the UPN restoration** immediately after enrollment — the window between modification and restoration should be seconds. Prolonged UPN changes increase the chance of detection or of the victim's authentication breaking (which generates helpdesk noise).

**Avoid PKINIT for high-value accounts from unusual hosts**: a PKINIT TGT request for `administrator@domain.com` from a workstation that has never previously used certificate authentication will stand out in any environment with reasonable Kerberos monitoring. Pass the NT hash from the PKINIT exchange (UnPAC) and use it for pass-the-hash lateral movement rather than using the cert directly for PKINIT from the attacker's host.

**Cleanup**: delete the issued certificate from the CA's database if possible. This requires CA manager rights and generates Event ID 4888 (certificate revoked) or 4890 (certificate manager settings changed), but removes the forensic artefact of the certificate itself. In most cases, simply letting the cert expire or not recovering it from disk is sufficient.

---

## 12. Detection and Defensive Indicators

### For Blue Teams

**Enable CA audit logging** — this is disabled by default on many CA deployments. Set `AuditFilter` to `127` on the CA and ensure the CA's security log is forwarded to SIEM. Without this, Event IDs 4886/4887/4888/4899 are not generated.

**Alert on Event ID 39** — any occurrence of KDC weak mapping fallback events should be treated as a high-fidelity indicator in environments that have deployed KB5014754. There is no legitimate reason for this event to fire in a well-maintained environment.

**Alert on `userPrincipalName` changes (4738)** — baseline UPN change frequency in the environment. In most domains this is effectively zero outside of HR-driven provisioning workflows. A 4738 followed within seconds by another 4738 on the same account (UPN set then restored) is ESC9 with high confidence.

**Audit `mspki-enrollment-flag` on templates** — any template with `CT_FLAG_NO_SECURITY_EXTENSION` set is an ESC9-vulnerable template. Enumerate these via LDAP and either remove the flag or restrict enrollment rights. PowerShell:

```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  -Filter {objectClass -eq "pKICertificateTemplate"} \
  -Properties mspki-enrollment-flag, mspki-certificate-name-flag, Name |
  Where-Object { ($_.'mspki-enrollment-flag' -band 0x00080000) -ne 0 }
```

**Enforce strong mapping** — set `StrongCertificateBindingEnforcement = 2` on all DCs. This eliminates ESC9 and ESC10 Case 1/2 as authentication paths entirely. Run in compatibility mode (`1`) first to identify legitimate certs that lack the extension and re-enroll them before moving to enforcement.

**Monitor `StrongCertificateBindingEnforcement` registry key** — any change to this key on a DC from `1` or `2` back to `0` is a critical indicator. This requires registry change monitoring (e.g., via Sysmon Event ID 13 on the DC or WMI registry event subscriptions).

### Summary: ESC9 vs ESC10 Detection Fingerprint

ESC9 leaves a template-issuance footprint (4886 on CA from an ESC9-flagged template) plus UPN modification events (4738 on DC) plus a weak mapping event (Event ID 39 on DC) plus a PKINIT TGT request (4768 PreAuth=17).

ESC10 leaves UPN modification events (4738) plus standard PKINIT events (4768 PreAuth=17) — no template-specific indicator because any auth template is usable. The distinguishing factor is the KDC registry state (`StrongCertificateBindingEnforcement = 0`), which itself should be a standing alert.
