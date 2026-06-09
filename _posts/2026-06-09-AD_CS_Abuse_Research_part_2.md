---
title: "AD CS Abuse Research, Part 2: Weak Mapping and the ESC9/ESC10 Attack Class"
date: 2026-06-08
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

This post covers the certificate-to-account mapping layer in Active Directory and how it becomes an attack surface. It walks through the KB5014754 strong mapping changes, the role of the szOID_NTDS_CA_SECURITY_EXT extension, and how ESC9 and ESC10 exploit weak UPN-based mapping to impersonate arbitrary principals without enrollee-supplied SANs or CA-level misconfigurations.

## Table of Contents

1. [Strong vs Weak Certificate Mapping (KB5014754)](#1-strong-vs-weak-certificate-mapping-kb5014754)
2. [ESC9: CT_FLAG_NO_SECURITY_EXTENSION](#2-esc9-ct_flag_no_security_extension)
3. [ESC10: Weak Certificate Mapping via Registry](#3-esc10-weak-certificate-mapping-via-registry)
4. [OPSEC Profile: ESC9 and ESC10](#4-opsec-profile-esc9-and-esc10)
5. [Detection and Defensive Indicators](#5-detection-and-defensive-indicators)

---

## 1. Strong vs Weak Certificate Mapping (KB5014754)

KB5014754 is the Microsoft patch that introduced strong certificate mapping for PKINIT. Understanding its three enforcement phases is essential for knowing when ESC9 and ESC10 apply.

### Background: The Problem KB5014754 Addressed

Before KB5014754, the KDC always used weak mapping: UPN-only lookup with no SID validation. This made ESC9-style attacks trivially possible on any domain regardless of template configuration, because any cert with any UPN in the SAN would be accepted. The patch introduced the `szOID_NTDS_CA_SECURITY_EXT` mechanism and changed the KDC's mapping behaviour based on a registry key and the presence of the extension in the presented certificate.

### The Three Modes

**Disabled (pre-patch or registry override)**: weak mapping always used. The KDC ignores `szOID_NTDS_CA_SECURITY_EXT` entirely even if present. ESC9 conditions are irrelevant because every certificate uses weak mapping.

**Compatibility mode (default after patch, before enforcement date)**: the KDC prefers strong mapping when the `szOID_NTDS_CA_SECURITY_EXT` extension is present and valid. If the extension is absent, the KDC falls back to weak mapping and logs a warning event (Event ID 39 on the DC). This is the mode where ESC9 applies: suppressing the extension forces the fallback to weak UPN mapping.

**Enforcement mode (enabled via registry or after Microsoft's enforcement deadline)**: the KDC requires the `szOID_NTDS_CA_SECURITY_EXT` extension. Certificates lacking it are rejected outright for PKINIT. In this mode, ESC9 no longer works for authentication; the cert will be issued but the KDC will refuse it.

The registry key controlling this on domain controllers is:

```
HKLM\SYSTEM\CurrentControlSet\Services\Kdc
Value: StrongCertificateBindingEnforcement
0 = Disabled (weak mapping always)
1 = Compatibility mode (default)
2 = Full enforcement
```

Enumerating this value on DCs is a prerequisite check for ESC9 exploitability. It is not readable via standard LDAP; it requires registry access to the DC, which typically means either local admin on the DC or a remote registry read via SMB if the `RemoteRegistry` service is running and accessible.

### What the `szOID_NTDS_CA_SECURITY_EXT` Extension Contains

The extension value is a DER-encoded structure containing the `objectSid` of the AD principal the CA associated with the certificate at issuance time. The CA populates this by looking up the authenticated requester's account in AD; it is not taken from the CSR and is not attacker-controlled in a normal ESC9 scenario.

In enforcement mode, the KDC:
1. Extracts the UPN from the SAN and finds the corresponding AD account
2. Extracts the SID from `szOID_NTDS_CA_SECURITY_EXT`
3. Validates that the SID in the extension matches the `objectSid` of the account found in step 1
4. Rejects if they do not match

A certificate with `administrator@domain.com` in the SAN UPN and the attacker's account SID in the extension will fail step 3 in enforcement mode, because the SID maps to the attacker's account, not Administrator.

---

## 2. ESC9: CT_FLAG_NO_SECURITY_EXTENSION

### Vulnerability Class

ESC9 is a certificate mapping bypass. Unlike ESC1, the template does not need to allow enrollee-supplied SANs; the certificate the attacker obtains will contain their own identity in the SAN. The attack works by forcing the KDC onto the weak UPN-only mapping path, then exploiting a mismatch between the UPN embedded in the cert (which was sourced from the attacker's or victim's AD account at issuance time) and the current state of that UPN in AD.

### Prerequisites

All of the following conditions must hold:

1. A certificate template has `CT_FLAG_NO_SECURITY_EXTENSION` (`0x00080000`) set in `mspki-enrollment-flag`
2. The template has an auth-enabling EKU (Client Authentication, Smart Card Logon, or Any Purpose)
3. The template is enrollable by a low-privilege principal (or by a principal the attacker controls)
4. The attacker has `GenericWrite` (or equivalent) over another AD user or computer account, specifically the ability to modify the `userPrincipalName` attribute of that account
5. The DC is in compatibility mode (not full enforcement) for certificate mapping; `StrongCertificateBindingEnforcement` is `0` or `1`

Condition 4 is what makes this different from ESC1. The attacker does not forge an arbitrary SAN; they temporarily modify a victim account's UPN to match a high-privilege target's UPN, enroll a certificate against the ESC9-vulnerable template (obtaining a cert with the manipulated UPN embedded), restore the original UPN, then use the cert (which now has the high-privilege UPN but the attacker's or victim's SID in the absent extension) for PKINIT.

### Attack Chain

**Step 1: Identify the target and the ESC9 template**

Enumerate certificate templates for `CT_FLAG_NO_SECURITY_EXTENSION` in `mspki-enrollment-flag` combined with an auth EKU and enrollment rights accessible to the attacker.

```
mspki-enrollment-flag & 0x00080000 == 0x00080000
```

**Step 2: Obtain GenericWrite over a victim account**

This is a lateral prerequisite: ESC9 does not give you GenericWrite, it requires it. Common sources: ACL misconfigurations found via BloodHound, WriteProperty on specific attributes delegated to a group the attacker is in, or an account the attacker already controls.

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

Request a certificate from the vulnerable template. Because `CT_FLAG_NO_SECURITY_EXTENSION` is set, the issued cert will not contain `szOID_NTDS_CA_SECURITY_EXT`. Because the victim account's UPN is now `administrator@domain.com`, the CA builds the SAN UPN from that value, so the cert will have `administrator@domain.com` in the SAN.

```bash
certipy req -u victimuser@domain.com -p Password1 \
  -ca 'CA-NAME' -template 'VulnerableTemplate' \
  -dc-ip 10.10.10.10
```

**Step 5: Restore the victim account's UPN**

Change `userPrincipalName` back to its original value before the modification is noticed or breaks other authentication. The issued certificate retains the `administrator@domain.com` UPN; changing the account's UPN back does not affect already-issued certificates.

```bash
certipy account update -u attacker@domain.com -p Password1 \
  -user victimuser -upn victimuser@domain.com
```

**Step 6: Authenticate using the certificate**

Submit the certificate for PKINIT. The KDC in compatibility mode sees `administrator@domain.com` in the SAN, looks up that UPN in AD, finds the Administrator account, checks for `szOID_NTDS_CA_SECURITY_EXT` (absent), logs a warning in compatibility mode (or silently accepts in disabled mode), and issues a TGT for Administrator.

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

### Why the SID Cross-check Fails to Catch This

The reason strong mapping breaks this attack is instructive: if `szOID_NTDS_CA_SECURITY_EXT` were present, it would contain the `objectSid` of whoever the CA looked up when it built the cert. In step 4, the CA looked up the victim account (because the attacker enrolled as the victim), so the extension would contain the *victim's* SID, not Administrator's SID. When the KDC tried to validate `administrator@domain.com` UPN against the victim's SID, the check would fail. The `CT_FLAG_NO_SECURITY_EXTENSION` flag prevents the extension from being written at all, forcing the KDC onto the UPN-only path where no such cross-check is performed.

### Variant: Attacker Controls Their Own Account

If the attacker controls a regular domain account and can write their own `userPrincipalName`, the attack simplifies: no need for GenericWrite over a victim. Modify own UPN to target's UPN, enroll on ESC9 template as self, restore UPN, authenticate. The enrolled cert's SAN will reflect whatever the UPN was at enrollment time.

---

## 3. ESC10: Weak Certificate Mapping via Registry

### Vulnerability Class

ESC10 is similar in outcome to ESC9 in that it exploits weak UPN-based certificate mapping, but the enablement condition is different. Rather than requiring a template flag that suppresses the security extension, ESC10 applies when the KDC has been explicitly configured to use weak mapping via the `StrongCertificateBindingEnforcement` registry key.

The SpecterOps research identifies two distinct ESC10 sub-cases, which are worth treating separately.

### ESC10 Case 1: KDC Weak Mapping with GenericWrite

**Prerequisite**: `StrongCertificateBindingEnforcement` on the DC(s) is set to `0` (disabled). In this state, the KDC always uses weak mapping regardless of whether certificates contain `szOID_NTDS_CA_SECURITY_EXT`. The extension is ignored completely.

The attack flow is nearly identical to ESC9 but requires no vulnerable template flag; *any* template with an auth EKU that builds the SAN from AD is usable. Because the KDC never checks the security extension, every certificate becomes a potential ESC9-equivalent.

**Prerequisites**:

1. `StrongCertificateBindingEnforcement = 0` on the DC (registry key, not readable via standard LDAP)
2. Any enrollable template with auth EKU that builds SAN from AD (no `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` needed)
3. `GenericWrite` over a target account to modify `userPrincipalName`

**Attack chain**: identical to ESC9: modify victim UPN, enroll cert (any suitable template), restore UPN, authenticate.

### ESC10 Case 2: KDC Weak Mapping without GenericWrite

**Prerequisite**: `StrongCertificateBindingEnforcement` is `0` AND `CertificateMappingMethods` on the DC includes the UPN mapping method (`0x4`).

This case is more interesting because it does not require write access to any account's UPN. It instead targets machine accounts and the `userPrincipalName` behaviour difference between user and computer objects.

Machine account objects (`CN=Computer,...`) do not have a `userPrincipalName` attribute by default; their Kerberos identity is based on `dNSHostName` and `sAMAccountName`. However, if a computer account is enrolled in a template that builds the SAN UPN from AD, the resulting UPN in the cert will be the `userPrincipalName` value if present, or fall back to a constructed value.

The specific chain here: if the attacker has write access to a computer account's `dNSHostName` attribute (which may be writable by the computer account itself or by accounts with delegated rights), they can set it to match a domain controller's hostname, enroll a cert in a machine-cert template, and obtain a cert that the KDC maps to the DC's machine account in weak mapping mode, enabling DCSync via pass-the-cert.

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

## 4. OPSEC Profile: ESC9 and ESC10

ESC9 and ESC10 generate a distinct log pattern compared to ESC1-style attacks because the certificate issuance looks entirely legitimate: the cert contains the attacker-controlled account's (or victim account's) identity, issued from a valid template with no anomalous SAN. The suspicious activity appears in AD object modification events and KDC authentication events, not in CA audit logs.

### CA-Side Events

**Event ID 4886 (Certificate Issued)**: Generated on the CA for every issued certificate. In ESC9/ESC10, this event will show a completely normal certificate issuance. The template name, the requester's identity, and the issued cert's subject will all appear legitimate. Unlike ESC1, there is no suspicious SAN present that would stand out. The only indicator is the template name; if the template has `CT_FLAG_NO_SECURITY_EXTENSION` set, a defender with deep template knowledge might flag certs from it as higher risk, but this requires custom detection logic.

CA audit logging must be enabled to see 4886 at all. Check with:
```
certutil -getreg CA\AuditFilter
```
A value of `0` means no auditing. `127` enables all audit events.

### DC-Side Events (KDC)

**Event ID 39 (Kerberos-Key-Distribution-Center)**: Generated when the KDC accepts a PKINIT authentication using weak mapping (certificate lacks `szOID_NTDS_CA_SECURITY_EXT` in compatibility mode). This is the most reliable detection indicator for ESC9. It explicitly logs the account name and certificate details. Defenders who monitor this event will catch ESC9 authentications in compatibility mode.

**Event ID 40**: Generated when a certificate is rejected due to mapping failure in enforcement mode. Seeing 40s after deploying enforcement is normal initially; sustained 40s are a sign of active exploitation attempts or legitimate certificates that need re-issuance.

**Event ID 4768 (Kerberos TGT Request)**: Standard TGT issuance event. For PKINIT authentications, the `Pre-Authentication Type` field will be `17` (PKINIT with DH) or `16` (PKINIT with RSA). Baseline what normal PKINIT looks like in the environment; service accounts and workstations using cert auth will generate these. Anomalies are unusual accounts suddenly using PKINIT, particularly privileged accounts.

### AD Object Modification Events (Domain Controller Security Log)

**Event ID 4738 (User Account Changed)**: Generated when `userPrincipalName` is modified. ESC9 requires changing a UPN, which generates this event with the old and new UPN values visible in the event data. In a normal environment, UPN changes are rare. Two 4738 events in quick succession on the same account (change to target UPN, then change back) is a near-certain ESC9 indicator.

**Event ID 4742 (Computer Account Changed)**: Same as 4738 but for computer objects. Relevant for ESC10 Case 2 chains involving `dNSHostName` modification.

### Noise Profile

| Activity | Events Generated | Baseline Frequency | Anomaly Threshold |
|---|---|---|---|
| UPN modification | 4738 on DC | Very rare in most environments | Any unexpected change |
| Certificate issuance | 4886 on CA | Moderate (normal enrollment) | Template-specific |
| PKINIT authentication | 4768 (PreAuth=17) on DC | Low-moderate | Privileged accounts using PKINIT |
| Weak mapping fallback | Event ID 39 on DC | Should be zero post-KB5014754 | Any occurrence |
| UPN restoration | 4738 on DC | Very rare | Paired with prior 4738 |

### OPSEC Hardening for Operators

The UPN modification is the noisiest step. Mitigations:

**Use accounts you already control** rather than modifying a victim's UPN. If the attacker's own account can enroll on the ESC9 template, and the attacker can write their own UPN (test this; it is sometimes permitted), the only 4738 event generated is for the attacker's own account. This is less suspicious than modifying another account's UPN.

**Time the UPN restoration** immediately after enrollment. The window between modification and restoration should be seconds. Prolonged UPN changes increase the chance of detection or of the victim's authentication breaking (which generates helpdesk noise).

**Avoid PKINIT for high-value accounts from unusual hosts**: a PKINIT TGT request for `administrator@domain.com` from a workstation that has never previously used certificate authentication will stand out in any environment with reasonable Kerberos monitoring. Pass the NT hash from the PKINIT exchange (UnPAC) and use it for pass-the-hash lateral movement rather than using the cert directly for PKINIT from the attacker's host.

**Cleanup**: delete the issued certificate from the CA's database if possible. This requires CA manager rights and generates Event ID 4888 (certificate revoked) or 4890 (certificate manager settings changed), but removes the forensic artefact of the certificate itself. In most cases, simply letting the cert expire or not recovering it from disk is sufficient.

---

## 5. Detection and Defensive Indicators

### For Blue Teams

**Enable CA audit logging**: this is disabled by default on many CA deployments. Set `AuditFilter` to `127` on the CA and ensure the CA's security log is forwarded to SIEM. Without this, Event IDs 4886/4887/4888/4899 are not generated.

**Alert on Event ID 39**: any occurrence of KDC weak mapping fallback events should be treated as a high-fidelity indicator in environments that have deployed KB5014754. There is no legitimate reason for this event to fire in a well-maintained environment.

**Alert on `userPrincipalName` changes (4738)**: baseline UPN change frequency in the environment. In most domains this is effectively zero outside of HR-driven provisioning workflows. A 4738 followed within seconds by another 4738 on the same account (UPN set then restored) is ESC9 with high confidence.

**Audit `mspki-enrollment-flag` on templates**: any template with `CT_FLAG_NO_SECURITY_EXTENSION` set is an ESC9-vulnerable template. Enumerate these via LDAP and either remove the flag or restrict enrollment rights. PowerShell:

```powershell
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com" \
  -Filter {objectClass -eq "pKICertificateTemplate"} \
  -Properties mspki-enrollment-flag, mspki-certificate-name-flag, Name |
  Where-Object { ($_.'mspki-enrollment-flag' -band 0x00080000) -ne 0 }
```

**Enforce strong mapping**: set `StrongCertificateBindingEnforcement = 2` on all DCs. This eliminates ESC9 and ESC10 Case 1/2 as authentication paths entirely. Run in compatibility mode (`1`) first to identify legitimate certs that lack the extension and re-enroll them before moving to enforcement.

**Monitor `StrongCertificateBindingEnforcement` registry key**: any change to this key on a DC from `1` or `2` back to `0` is a critical indicator. This requires registry change monitoring (e.g., via Sysmon Event ID 13 on the DC or WMI registry event subscriptions).

### Summary: ESC9 vs ESC10 Detection Fingerprint

ESC9 leaves a template-issuance footprint (4886 on CA from an ESC9-flagged template) plus UPN modification events (4738 on DC) plus a weak mapping event (Event ID 39 on DC) plus a PKINIT TGT request (4768 PreAuth=17).

ESC10 leaves UPN modification events (4738) plus standard PKINIT events (4768 PreAuth=17) with no template-specific indicator, because any auth template is usable. The distinguishing factor is the KDC registry state (`StrongCertificateBindingEnforcement = 0`), which itself should be a standing alert.

---

*Next: Part 3: AD Object Write Primitives (ESC4, ESC5, ESC7, ESC14)*
