---
title: "AD CS Abuse Research, Part 1: PKI Internals and Certificate Enrollment"
date: 2026-06-04
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

This post covers the foundational mechanics of Active Directory Certificate Services: how the PKI trust model is structured in AD, where configuration lives in the directory, what certificate template attributes control at the CA level, how the enrollment flow works end to end, and how PKINIT exchanges a certificate for a Kerberos TGT. It closes with a taxonomy of the ESC attack surface as a map for the rest of the series.

## Table of Contents

1. [What AD CS Actually Is](#1-what-ad-cs-actually-is)
2. [The PKI Trust Model in Active Directory](#2-the-pki-trust-model-in-active-directory)
3. [Where Everything Lives: The Configuration Partition](#3-where-everything-lives-the-configuration-partition)
4. [Certificate Templates: The Attributes That Matter](#4-certificate-templates-the-attributes-that-matter)
5. [The Enrollment Flow End to End](#5-the-enrollment-flow-end-to-end)
6. [PKINIT: Certificate to TGT](#6-pkinit-certificate-to-tgt)
7. [The ESC Taxonomy: A Map of the Attack Surface](#7-the-esc-taxonomy-a-map-of-the-attack-surface)

---

## 1. What AD CS Actually Is

Active Directory Certificate Services is Microsoft's implementation of a Public Key Infrastructure baked directly into Active Directory. The concept of a PKI is not Microsoft-specific; it is the broader framework of using asymmetric cryptography to establish trust between parties who have never directly negotiated a secret. A Certificate Authority sits at the centre of that framework: it is a trusted third party that signs certificates binding a public key to an identity, and anyone who trusts the CA can trust those bindings.

What makes AD CS distinct from a generic PKI deployment is that it reuses Active Directory's existing identity store rather than maintaining its own. The CA does not have its own user database; when it needs to know who someone is, it queries AD. When it needs to know what a principal is allowed to request, it reads ACLs on AD objects. When it issues a certificate, the identity embedded in that certificate is sourced from AD attributes. This tight coupling is what makes AD CS misconfigurations so severe: a flaw in the PKI layer translates directly into domain authentication compromise because certificates are accepted as first-class credentials by Kerberos.

Certificates issued by an enterprise CA are used throughout AD environments for:

- **Kerberos authentication** via PKINIT: a certificate with the right EKU can be exchanged for a TGT without a password
- **LDAPS / TLS**: securing LDAP over TLS using domain controller certificates
- **Smart card logon**: hardware-backed authentication using cert-bound keys
- **Code signing, email encryption, EFS**: various application-layer PKI uses

Of these, PKINIT is the primary attack path. It is the mechanism by which a certificate becomes a Kerberos credential, and it is what every ESC ultimately targets.

---

## 2. The PKI Trust Model in Active Directory

The trust chain in an AD CS deployment has three layers:

**The Root CA** is the ultimate trust anchor. Its certificate is self-signed and distributed to every machine in the domain via Group Policy, landing in the `Trusted Root Certification Authorities` store. Trusting the root CA means trusting every certificate it signs, directly or transitively.

**The Issuing (Enterprise) CA** is the CA that actually handles enrollment requests from domain members. In most environments this is the same machine as the root CA (a combined root/issuing CA), though larger deployments separate them. The issuing CA's certificate is signed by the root CA and is distributed to the `Intermediate Certification Authorities` store domain-wide. All certificates issued to users and computers are signed by the issuing CA's private key.

**Issued certificates** are the leaf nodes: the actual certs held by users, computers, and services. Their validity depends entirely on the chain back to the trusted root.

The critical security property of this model: **trusting the CA means trusting every certificate it issues, for the lifetime of those certificates.** A compromised or misconfigured CA does not just compromise one credential; it compromises the authentication fabric of the entire domain. An attacker who can obtain a certificate naming a Domain Admin from a trusted CA has a persistent credential that survives password resets, account lockouts, and in many cases even account deletion, until certificate revocation is enforced.

### Why Certificate Auth is Powerful for Attackers

Password-based Kerberos authentication is ephemeral from an attacker's perspective: a password change kills the TGT, and the new TGT requires the new password. Certificate-based authentication via PKINIT is different: the credential is the certificate itself, signed by the CA, valid for the certificate's entire validity period (commonly one to two years for user templates). A password reset does not revoke a certificate. The certificate's binding is to an identity (the UPN or SAN embedded at issuance time), not to a secret the victim controls.

This is why ESC exploitation is so impactful relative to effort: a single certificate request, if the template is misconfigured, yields a multi-year authentication credential for any principal the attacker names.

---

## 3. Where Everything Lives: The Configuration Partition

All AD CS configuration is stored in the Active Directory Configuration partition, which is replicated domain-wide and readable by all authenticated users by default. This is enumerable without elevated privileges using standard LDAP queries, which is why Certipy's `find` command works with any domain account.

The base path is:

```
CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com
```

The key containers under this path:

**`CN=Certificate Templates`**: one AD object per template. This is where template configuration lives: which EKUs are included, what subject/SAN flags are set, what enrollment permissions are granted, and how many RA signatures are required. The `nTSecurityDescriptor` on each template object controls who can enroll and who has write access.

**`CN=Enrollment Services`**: one AD object per enterprise CA. Each object lists the templates published on that CA (`certificateTemplates` attribute) and carries the CA-level configuration flags that override template behaviour.

**`CN=NTAuthCertificates`**: a single object whose `cACertificate` attribute contains the certificates of every CA trusted for PKINIT and smart card logon. A CA must appear here for certificates it issues to be accepted by domain controllers for Kerberos authentication. This is the object targeted by the Golden Certificate technique; adding a rogue CA certificate here makes the KDC trust forged certificates from an attacker-controlled CA.

**`CN=AIA`** and **`CN=CDP`**: Authority Information Access and CRL Distribution Points. These define where clients fetch the CA certificate chain and certificate revocation lists. Relevant for OPSEC: CRL fetches can generate network noise when certificates are validated.

---

## 4. Certificate Templates: The Attributes That Matter

A certificate template is an AD object that acts as a policy specification: it tells the CA what kind of certificate to issue, to whom, and with what content. Understanding the key LDAP attributes is essential for both exploitation and for building tooling that correctly identifies vulnerable conditions.

### `mspki-certificate-name-flag`

This integer attribute is a bitmask controlling how the certificate's Subject and Subject Alternative Name fields are populated.

The flag that matters most for exploitation is `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (`0x00000001`). When this bit is set, the CA accepts the Subject Distinguished Name and SAN directly from the submitted CSR rather than building them from the requester's AD attributes. The CA does not validate that the requester is entitled to the identity they are claiming in the CSR; it simply embeds whatever was in the request. This is the root condition for ESC1: combined with an auth-enabling EKU and low-privilege enrollment rights, it allows any enrollee to obtain a certificate naming an arbitrary principal.

A second relevant flag is `CT_FLAG_SUBJECT_ALT_REQUIRE_UPN` (`0x00000400`). When set, the CA constructs the SAN UPN from the requester's AD `userPrincipalName`, meaning the identity in the cert is always the actual requester. This flag's absence (when `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is also absent) leaves SAN construction to the CA's default behaviour, which is to build it from AD.

### `mspki-enrollment-flag`

Another bitmask, controlling enrollment behaviour rather than subject construction.

`CT_FLAG_NO_SECURITY_EXTENSION` (`0x00080000`) is the flag directly relevant to ESC9. When set, the CA does not embed the `szOID_NTDS_CA_SECURITY_EXT` OID (`1.3.6.1.4.1.311.25.2`) extension in issued certificates. This extension, introduced with KB5014754, carries the `objectSid` of the AD account the CA looked up at issuance time. Domain controllers in enforcement mode require this extension and cross-validate the SID it contains against the account whose UPN appears in the SAN. Suppressing the extension downgrades authentication to weak mapping: UPN-only, with no SID validation.

`CT_FLAG_PEND_ALL_REQUESTS` (`0x00000002`) is worth noting for OPSEC: when set, all requests go to a pending queue requiring CA manager approval before issuance. Templates without this flag issue immediately, which is the norm for exploitable templates.

### `pKIExtendedKeyUsage`

A multi-valued attribute containing the EKU OIDs the CA will embed in issued certificates. For PKINIT to succeed, the certificate needs at least one of:

- `1.3.6.1.5.5.7.3.2` (Client Authentication)
- `1.3.6.1.4.1.311.20.2.2` (Smart Card Logon)
- `1.3.6.1.5.2.3.4` (PKINIT Client Auth, less common)
- `2.5.29.37.0` (Any Purpose; ESC2: accepts any use including authentication)

A certificate with no EKU at all is also usable for authentication in some configurations, since absence of EKU constraints means the certificate is valid for all purposes.

The `Certificate Request Agent` OID (`1.3.6.1.4.1.311.20.2.1`) is the enrollment agent EKU. A certificate bearing this OID can be used to request certificates *on behalf of other principals*, which is the mechanism behind ESC3.

### `mspki-ra-signature`

An integer specifying how many Registration Authority (enrollment agent) counter-signatures are required on a CSR before the CA will issue against this template. A value of `0` means no counter-signature is required; the CSR can be submitted directly. For ESC3 to be exploitable, this must be `0` on the target template (the one being enrolled via the enrollment agent).

### `nTSecurityDescriptor`

The access control list on the template object. Two distinct sets of rights matter:

**Enrollment rights**: the `Certificate-Enrollment` extended right (`0e10c968-78fb-11d2-90d4-00c04f79dc55`) allows a principal to request a certificate from this template. When `Authenticated Users`, `Domain Users`, or `Domain Computers` holds Allow on this right, the template is low-privilege enrollable.

**Write rights**: `WriteProperty`, `WriteDacl`, `WriteOwner`, and `GenericWrite` on the template object allow modifying the template's configuration attributes. This is the ESC4 condition: write access to a template allows an attacker to set `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` and an auth EKU, converting the template into an ESC1-exploitable state.

### CA-Level: `EDITF_ATTRIBUTESUBJECTALTNAME2`

This flag lives on the CA object in `CN=Enrollment Services`, not on individual templates. When set (value `0x40` in the CA's policy edit flags), it instructs the CA to accept SAN values from the CSR on *any* template, regardless of that template's individual `mspki-certificate-name-flag` settings. It is set via `certutil -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA server and constitutes ESC6. Detecting it requires reading the CA object's attributes, not just the template objects.

---

## 5. The Enrollment Flow End to End

Understanding exactly what happens during a certificate request, and which party controls what, is the foundation for understanding why each ESC works.

### Step 1: Key pair generation

The client generates an RSA or ECC key pair locally. The private key never leaves the client (in normal operation). The public key will be embedded in the CSR and ultimately in the issued certificate, binding the cert to this specific key material.

### Step 2: CSR construction (PKCS#10)

The client constructs a Certificate Signing Request, a PKCS#10 structure containing:

- The public key
- The requested Subject Distinguished Name (e.g., `CN=User,DC=domain,DC=com`)
- Any requested extensions, including a proposed SAN if the template permits it
- A signature over the CSR using the private key, proving the requester possesses the private key corresponding to the submitted public key

The Subject and SAN values in the CSR are *requests*, not guarantees. Whether the CA honours them, overrides them, or rejects them depends entirely on the template's `mspki-certificate-name-flag` and the CA-level `EDITF_ATTRIBUTESUBJECTALTNAME2` flag.

### Step 3: LDAP template lookup

Before submitting, the client reads the target template's attributes from `CN=Certificate Templates` via LDAP to confirm the template is published on an accessible CA and to determine what the request should look like.

### Step 4: Transport authentication and CSR submission

The client authenticates to the CA and submits the CSR. The transport and interface determine how authentication occurs:

- **MS-WCCE over named pipe (`\pipe\cert`)**: authentication is handled by the SMB session over port 445. The CA's policy module receives the request and calls `GetSecurityContext()` to identify the requester; it sees the SMB session's authenticated identity. NTLM or Kerberos, depending on what the client negotiated.
- **MS-ICPR over named pipe (`\pipe\ICertPassage`) or TCP**: the older RPC interface, same auth model but a different binding. This is the ESC11 target.
- **HTTP enrollment (`/certsrv`)**: authentication via HTTP NTLM or Kerberos. This endpoint does not require HTTPS by default and is the ESC8 relay target.

The template name is passed as part of the request attributes, not inside the CSR itself.

### Step 5: CA permission checks

The CA performs two sequential permission checks:

First, it checks its own enrollment permissions via the `nTSecurityDescriptor` on the CA object in `CN=Enrollment Services`. The authenticated identity must have `Certificate-Enrollment` allow on the CA object. This check is almost universally passed in domain environments because CAs are typically configured to allow `Authenticated Users` to enroll.

Second, it checks the template's enrollment permissions via the `nTSecurityDescriptor` on the specific template object in `CN=Certificate Templates`. Again, `Certificate-Enrollment` allow on the requester's identity (or a group it belongs to) is required.

Both checks use the **transport-layer security context**: whoever authenticated at the SMB or HTTP layer. This is why NTLM relay attacks work: the relayed identity passes both permission checks, and the CSR content (including any attacker-controlled SAN) is processed under that identity's context.

### Step 6: Template policy validation

The CA policy module processes the CSR against the template's configuration:

- Verifies the request signature (proof of private key possession)
- Checks whether the template requires manager approval (`CT_FLAG_PEND_ALL_REQUESTS`)
- Checks whether an RA counter-signature is required (`mspki-ra-signature`)
- Evaluates the requested Subject and SAN against `mspki-certificate-name-flag` to determine whether to use values from the CSR or build from AD
- Validates or overrides the requested EKU against `pKIExtendedKeyUsage`

### Step 7: Certificate construction

If all checks pass, the CA builds the certificate. For the Subject and SAN:

- If `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` is set: values are taken from the CSR as submitted
- If not: the CA queries AD using the requester's identity and builds the Subject from the account's `distinguishedName` and the SAN UPN from `userPrincipalName`

The CA then adds extensions. Critically, unless `CT_FLAG_NO_SECURITY_EXTENSION` is set on the template, it embeds `szOID_NTDS_CA_SECURITY_EXT` containing the `objectSid` of the AD account it looked up for the requester. This extension is what strong certificate mapping depends on.

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

The client's signature over the AS request body serves the same purpose as knowing the password in standard Kerberos: it proves the client possesses the private key bound to the certificate.

### KDC Validation

The KDC (running on the DC) processes the `PA-PK-AS-REQ` by:

1. Validating the certificate chain up to a CA in `CN=NTAuthCertificates`
2. Verifying the EKU (the cert must have Client Authentication, Smart Card Logon, or equivalent)
3. Checking certificate revocation (CRL or OCSP) if configured, though this is often not enforced in practice
4. Mapping the certificate to an AD account (detailed in the next section)
5. Constructing the PAC for the mapped account and issuing the TGT

### Certificate-to-Account Mapping

This step is where the attack surface lives. The KDC must determine *which AD account* the certificate represents. There are two mechanisms:

**Strong mapping** uses the `szOID_NTDS_CA_SECURITY_EXT` extension embedded in the certificate. The KDC extracts the `objectSid` from this extension and looks up the account with that SID directly. The UPN in the SAN is also verified to match that account. Because the SID in the extension was written by the CA at issuance time based on the *actual requester's* AD account, a certificate with a manipulated UPN but a legitimate requester's SID will fail strong mapping, since the SID and UPN point to different accounts.

**Weak mapping** falls back to UPN-only lookup. The KDC extracts the UPN from the SAN, queries AD for `userPrincipalName` matching that value, and issues a TGT for whatever account it finds. There is no cross-validation with a SID. A certificate with `administrator@domain.com` in the SAN UPN will map to the Administrator account regardless of who originally requested the certificate.

This mapping asymmetry is the root cause of ESC9 and ESC10.

### UnPAC-the-Hash

A PKINIT quirk worth noting: the AS-REP in a PKINIT exchange encrypts the session key using the client's public key (Diffie-Hellman key agreement, specifically). Because the session key is not derived from the account's NT hash, the AS-REP does not contain material that can be used to recover the NT hash, except via a specific technique. The KDC also encrypts the session key under the account's NT hash in the `enc-pa-data` field for compatibility. Requesting the session key via `U2U` (User-to-User) allows recovering the NT hash from the PKINIT exchange, which is what tools like Certipy's `auth -pfx` do when they print the NT hash alongside the TGT. This is useful because the hash can be passed directly for lateral movement without needing a PKINIT-capable service.

---

## 7. The ESC Taxonomy: A Map of the Attack Surface

The ESC numbering (ESC1 through ESC15+) originated in the SpecterOps whitepaper "Certified Pre-Owned" and has been extended by subsequent research. Each ESC identifies a distinct misconfiguration class, though many chains involve multiple ESCs.

A useful mental model groups them by what layer they attack:

**Template misconfiguration (ESC1–4, ESC9)**: flaws in how an individual template is configured. Exploitable by any principal with enrollment rights on that template.

**CA misconfiguration (ESC6, ESC7, ESC8, ESC11)**: flaws in how the CA itself is configured or secured. Often higher impact because they affect all templates published on that CA.

**Certificate mapping bypass (ESC9, ESC10)**: attacks that exploit weak certificate-to-account mapping at the KDC level rather than manipulating what the CA issues.

**AD object write (ESC4, ESC5, ESC7, ESC14, ESC15)**: attacks that begin with write access to an AD or CA object and modify configuration to enable a certificate-based authentication path.

The distinction between "CA trusts wrong identity" (ESC1–4, ESC6–8) and "KDC maps cert to wrong account" (ESC9–10) is important for tooling and OPSEC: the former generates CA audit events at the issuance stage, while the latter generates KDC events at the authentication stage, with the issuance appearing entirely normal.

---

*Next: Part 2: Weak Certificate Mapping (ESC9 & ESC10)*
