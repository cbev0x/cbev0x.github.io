---
title: "Windows Authentication Coercion to NTLM Relay, Part 4: LDAP/LDAPS Relay and ESC8 Against Server 2025 Defaults"
date: 2026-06-27
categories: [Personal]
tags: [Windows, Active Directory, Relay, Privilege Escalation, Research]
published: true
---

> All testing in this writeup was performed in an isolated, fully self-contained lab environment (corp.lab) with no internet connectivity and no production systems involved. This research is for educational and defensive purposes only. Do not attempt any of the techniques described here against systems you do not own or do not have explicit written authorization to test.

## Section 1: NTLM MIC enforcement blocks SMB-sourced relay to LDAP/LDAPS

### Background

CVE-2019-1040 ("Drop the MIC") originally allowed an attacker to strip the Message Integrity Check (MIC) field from a captured NTLM AUTHENTICATE message and relay it across protocols, bypassing signing negotiation in the process. Microsoft's June 2019 patch hardened MIC validation on the server side to close this. That hardening has been part of the patched baseline across all supported Windows versions since 2019 — it is not a feature unique to Server 2025. What this section confirms is that a fully patched, default Server 2025 build enforces that validation, which closes off a relay path that a large amount of public coercion-to-relay research still assumes is open.

Part 3's PrinterBug test also produced a successful relay, which might look like it contradicts this section's result at first glance. It doesn't: Part 3 relayed an SMB-sourced authentication to another SMB target (`SRV02$` to SRV01 over SMB), which is same-protocol relay and never needs the signing flag tampered with. MIC enforcement specifically targets the case tested here, an SMB-sourced authentication relayed across protocols into LDAP or LDAPS, which is exactly the scenario the original CVE-2019-1040 bypass was built around.

### Test setup

- Trigger: PrinterBug (MS-RPRN) coercion against DC01 (192.168.50.10), originating from a low-privilege account (`coercetest`)
- Relay listener: `impacket-ntlmrelayx` on Kali (192.168.50.50)
- Relay target: DC01, first over plaintext LDAP, then over LDAPS

### Finding

Running `ntlmrelayx` with `--remove-mic` against LDAP produced an immediate authentication failure:

```
SEC_E_INVALID_TOKEN (0x80090308)
```

This result on its own is ambiguous — it could mean either a malformed MIC-stripped token specific to this Impacket build, or genuine MIC enforcement on the DC. To rule out the protocol as the variable, the same coercion-to-relay chain was repeated against LDAPS instead of plaintext LDAP. The result was the same failure pattern: a "client requested signing" warning immediately followed by `STATUS_ACCESS_DENIED`, even with a valid certificate in place on the LDAPS listener.

Because the failure was identical regardless of whether the relay target was LDAP or LDAPS, the failure point sits below both protocols' own signing/channel-binding logic. The token itself is being rejected before either policy is ever evaluated.

### Conclusion

Default Server 2025 enforces NTLM MIC validation on inbound authentication. This means:

- SMB-sourced coercion (PrinterBug, PetitPotam-via-SMB) relayed into LDAP or LDAPS is not viable on this build, full stop — independent of LDAP signing or channel binding configuration.
- The signing/channel-binding comparison originally planned for this matrix cell (LDAP unsigned vs. LDAPS channel binding off vs. on) is moot for this specific coercion-to-relay path, because the chain never survives long enough to reach that policy layer.
- This is a meaningfully different and more current result than most public "coercion to LDAP relay" writeups assume, since a large share of that material predates consistent MIC enforcement being validated against a clean, fully patched 2025 baseline.
- The only theoretical path left open for this matrix cell is HTTP-sourced coercion, since HTTP-originated NTLM negotiations are not subject to the same SMB-side signing flag that triggers this rejection. That path is picked up in Section 2 below, via the ADCS HTTP enrollment endpoint (ESC8).

### Detection note

Both failed relay attempts surfaced cleanly in the Elastic stack as failed authentication events on DC01, correlating with the originating coercion request. No successful logon (Event ID 4624) was ever generated on the relay target, since the chain failed at the NTLM integrity layer before a session could be established — meaning a defender doesn't even need session-level telemetry to catch this attempt; the authentication failure itself is the signal.

---

## Section 2: ESC8 default relay defenses (Server 2025 + default ADCS)

### Background

ESC8 is the classic NTLM-relay-to-certificate-issuance abuse path: coerce a machine account into authenticating, relay that authentication into a CA's HTTP(S) web enrollment endpoint (certsrv), and use the resulting session to request a certificate as the coerced identity. Most public ESC8 guidance treats this as viable by default unless an administrator has manually enabled Extended Protection for Authentication (EPA) on the CA's IIS site. This section tests whether that assumption still holds on a clean Server 2025 build with a default AD CS + Web Enrollment install.

### Test setup

- CA: `corplab-CS2-CA`, Enterprise Root CA installed fresh on SRV02 (192.168.50.12), a dedicated member server, deliberately kept off the domain controller per Microsoft's own placement guidance.
- Web Enrollment role installed and bound to HTTPS only; plain HTTP enrollment is disabled by default on this build (confirmed both by direct browser/curl testing and by certipy's CA enumeration).
- Coercion source: SRV01 (192.168.50.11), with the WebDAV Redirector feature installed to enable the WebClient service, and EFS manually started to expose the EFSRPC interface, both needed since neither ships running by default on this build.
- Trigger: PetitPotam (MS-EFSR), `efsr` named pipe, against SRV01, pointed at a Kali-hosted relay listener.
- Relay: `impacket-ntlmrelayx --adcs`, targeting `https://srv02.corp.lab/certsrv/certfnsh.asp`.

### Enumeration finding

`certipy-ad find -vulnerable` against the CA returned:

```
Web Enrollment
  HTTP
    Enabled : False
  HTTPS
    Enabled : True
    Channel Binding (EPA) : True
```

EPA channel binding is enabled by default on this build's web enrollment endpoint, not something an administrator had to turn on manually.

This was independently verified at the IIS configuration level, not just through certipy's inference. Querying the actual `windowsAuthentication/extendedProtection` element on the CertSrv application returned:

```xml
<extendedProtection tokenChecking="Require">
</extendedProtection>
```

`tokenChecking="Require"` is the literal IIS setting controlling EPA enforcement, and it was already set this way immediately after running `Install-WindowsFeature ADCS-Web-Enrollment` and `Install-AdcsWebEnrollment -Force`. No manual IIS Authentication configuration was performed at any point. This matters because every piece of existing public guidance on this topic, including Microsoft's own KB5005413, describes EPA on AD CS web enrollment as something an administrator must explicitly configure, never as a default. That guidance isn't wrong for the OS versions it was written against, but it appears `Install-AdcsWebEnrollment` on Server 2025 now sets `tokenChecking="Require"` automatically as part of role installation, which is a more specific and more current claim than "EPA is on by default" and isn't documented anywhere in the existing material reviewed for this research.

### Relay finding

The coercion succeeded cleanly (PetitPotam returned its expected `ERROR_BAD_NETPATH` success indicator), and the relay listener received the resulting `SRV01$` machine account authentication and attempted to relay it against the CA's HTTPS endpoint. The attempt failed:

```
[-] (SMB): Authenticating against https://srv02.corp.lab as CORP/SRV01$ FAILED
```

IIS's own logs on SRV02 confirm the precise reason. The relevant log line:

```
401 1 3221226331
```

`3221226331` decimal is `0xc000035b`, which Microsoft's own error reference defines as: the client's supplied SSPI channel bindings were incorrect. This is not a generic credential failure — it is EPA's specific, purpose-built rejection for an authentication that arrives without a valid channel binding token tied to the TLS session it's riding on, which is exactly the situation a relayed (man-in-the-middled) NTLM authentication produces.

### Conclusion

Default Server 2025 + default AD CS Web Enrollment enforces EPA out of the box. The classic ESC8 coercion-to-relay chain, when attempted against this configuration, fails at the channel-binding validation step rather than succeeding the way most existing public ESC8 writeups assume.

This result is structurally parallel to Section 1's finding even though the underlying control is different:

| | Section 1 (LDAP/LDAPS) | Section 2 (ESC8/ADCS) |
|---|---|---|
| Control enforced | NTLM MIC validation | EPA / channel binding |
| Confirmed via | `SEC_E_INVALID_TOKEN` (0x80090308) | `0xc000035b`, channel bindings incorrect |
| Result | SMB-sourced relay to LDAP/LDAPS blocked | HTTP-sourced coercion relayed into ESC8 blocked |

Taken together, both sections support the same overall thesis for this writeup series: the exploitability of the coercion-to-relay matrix in 2026 is determined less by which Windows Server version is running and more by which specific control surface (MIC, EPA, signing) a given relay target enforces by default, and on a clean Server 2025 baseline, more of those controls are on out of the box than older, widely-cited research assumes.

### Detection note

The relay attempt is fully visible without any session-level telemetry: the IIS log entry itself (`401`, substatus `1`, win32-status `3221226331`) is a direct, unambiguous indicator of an attempted channel-binding bypass and should be a monitored signal on any CA web enrollment endpoint. No certificate was issued and no successful authentication occurred at any point in the chain.
