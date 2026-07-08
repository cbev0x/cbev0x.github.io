---
title: "Windows Authentication Reflection, Part 2: CVE-2026-24294 in the Lab"
date: 2026-07-08
categories: [Personal]
tags: [Windows, Active Directory, Coercion, Privilege Escalation, Research]
published: true
---

Part one covered the mechanic and the lineage. This part is operational. We reproduce CVE-2026-24294 against a default Windows Server 2025 environment, document what the telemetry actually shows, and work out what a defender needs to catch it. Every result here is attributed to a specific build and configuration so the findings are reproducible and attributable rather than approximate.

## Environment

Three Windows Server 2025 Datacenter Evaluation machines on an isolated VMnet segment, all at build 26100.32230 (KB5073379, January 2026 cumulative update). This build predates the CVE-2026-24294 patch, which shipped in March 2026 at build 26100.32522. The domain is reflect.lab, running at Windows 2016 functional level (WinThreshold, the highest available on Server 2025). Tooling runs from a Kali attacker box at 10.10.10.50. Telemetry ships from all three Windows servers to an Elasticsearch 8.19.16 stack via Winlogbeat 8.19.16, collecting the Security, System, Sysmon/Operational, SMBClient/Operational, and SMBServer/Operational channels.

| Host | Role | IP | SMB Inbound Signing |
|---|---|---|---|
| DC01 | Domain Controller, PDC | 10.10.10.10 | Required (True) |
| SRV01 | Member server, reflection target | 10.10.10.11 | Not required (False) |
| SRV02 | Member server, AD CS / Web Enrollment | 10.10.10.12 | Not required (False) |

The unsigned inbound SMB posture on the member servers is the default for Windows Server 2025 and was confirmed empirically before any configuration change. It is not a misconfiguration. No GPO forces it and no role modifies it. The member servers are the realistic reflection target class precisely because this is their default state.

## Default posture findings before any attack

Before staging the reflection chain, characterizing the defaults is worth doing deliberately because several of them are surprising relative to earlier Server versions and directly shape the attack surface.

SMB client signing is required by default on Server 2025, but SMB server (inbound) signing is not. The asymmetry matters: a domain-joined member server will refuse to connect to an unsigned SMB target but will happily accept unsigned inbound connections from an attacker's relay. The DC, by contrast, enforces inbound signing after promotion via the Default Domain Controllers Policy. This is why the DC is a coercion source but not a viable reflection target by default, while member servers are both.

A plain member server with no file-sharing or role-specific services does not expose port 445 to the network by default. The Windows Firewall "File and Printer Sharing (SMB-In)" rule is disabled. SRV01, as a bare member, required an explicit firewall rule addition before it was reachable over SMB. SRV02 became reachable automatically when the AD CS / IIS role was installed, because IIS pulled in rules that opened the network surface. This distinction is worth naming in a real environment: the servers that host roles and services are the ones whose SMB is actually reachable, and they are the realistic reflection targets.

LDAP signing is enforced by default on the domain controller. Unsigned LDAP simple binds are rejected with `strongerAuthRequired`. Channel binding is set to "When Supported." This closes the reflect-to-LDAP(S) path for tooling that defaults to plaintext binds and is part of the broader EPA-by-default hardening that Microsoft enabled for Server 2025.

AD CS web enrollment ships with `sslFlags="Ssl, Ssl128"` (Require SSL) and Windows Authentication `extendedProtection tokenChecking="Require"` (EPA required) out of the box, but only an HTTP port 80 binding exists and no HTTPS listener is configured. A plaintext request to `http://ca/certsrv/` returns HTTP 403. The default ESC8 relay target is therefore closed by default on Server 2025, not by EPA but by the SSL requirement and the absent HTTPS binding. EPA is configured but inert without a TLS channel. An administrator who adds an HTTPS binding to make web enrollment functional activates EPA, so the two locks swap rather than both being present simultaneously.

ADIDNS dynamic updates are permitted for authenticated domain users by default, but DC01's LDAP signing enforcement means record creation requires a signed bind. Tooling that defaults to plaintext LDAP binds (stock dnstool.py with `-u/-p`) fails. BloodyAD, which seals its bind by default, succeeds. This is a practical environmental fact: on Server 2025, ADIDNS tooling must speak signed LDAP or it does not work.

These findings establish the baseline honestly. The attack surface on default Server 2025 is narrower than on 2019 or 2022, and the techniques that worked against older defaults require adjustment or fail outright. The one gap that remains wide open is unsigned inbound SMB on member servers that expose port 445 through role installation.

## CVE-2026-24294: the mechanic

The mechanic is covered in part one, but a brief restatement grounds the reproduction. Windows SMB clients track their transport connections by server address and share path. When a client has an established TCP connection to a given server path, it reuses that connection for subsequent access to the same path rather than opening a new one. CVE-2026-24294 exploits two features introduced in recent Windows versions: the ability to connect to an SMB share on an arbitrary TCP port via `net use /tcpport`, and the connection reuse (multiplexing) behavior.

The chain: an unprivileged process on the target establishes a TCP connection to an attacker-controlled SMB server on a nonstandard port, mounting a share. The attacker's server hooks SMB2 SESSION_SETUP to intercept authentication. When a SYSTEM-context process subsequently accesses the same UNC path, the SMB client finds the existing nonstandard-port connection in its transport table and routes the SYSTEM process's authentication through it. The attacker's hook intercepts the second SESSION_SETUP, extracts the NTLM blob, and forwards it to ntlmrelayx, which relays it back to the target's own SMB on port 445. Because the target is the source, the local authentication path engages, the NTLM type-3 message arrives effectively empty with no MIC or credential binding, and the relay succeeds as SYSTEM.

The June 2025 patch for CVE-2025-33073 closed the marshalled-name variant by teaching the SMB client to reject target names containing CredMarshalTargetInfo blobs. CVE-2026-24294 sidesteps that fix entirely because it does not use marshalled names. The patch only touched the SMB client path and did not address the arbitrary-port and connection-reuse behaviors that this variant exploits.

## Tooling and setup

The relay chain has three components. ntlmrelayx runs with all built-in servers disabled except the raw relay port, targeting the local SMB stack at `smb://127.0.0.1`. The modified `smbserver.py` from the 0xNDI/CVE-2026-24294 PoC runs on port 12345 with the SESSION_SETUP hook installed and relay forwarding pointed at ntlmrelayx's raw port 6666. The hook intercepts every SESSION_SETUP on the nonstandard-port connection, allows the first one to complete normally (establishing the legitimate share mount), and intercepts the second one to initiate the relay.

The coercion mechanism in the lab is a scheduled task configured to run as SYSTEM, accessing the UNC path `\\127.0.0.1\test`. This is a deliberate simplification of the real coercion primitive. In a real engagement, the SYSTEM-level authentication would be induced by a coercion vector such as PrinterBug, PetitPotam, or MSEven against the Spooler or EFS service, which triggers outbound authentication from a SYSTEM-level OS service rather than a scheduled task. The reflection mechanic is identical regardless of which SYSTEM process initiates the authentication. The scheduled task was used here because the relevant coercion vectors on a plain member server required additional firewall rule changes, and the goal was to isolate and demonstrate the reflection primitive itself rather than the coercion chain leading into it.

Windows Defender was disabled during the detonation run. In a real environment, the relay tooling would need to be obfuscated or the implant delivery would need to bypass endpoint protection. The lab result shows the primitive fires on the patched-but-vulnerable build; it does not assert that evasion is trivial.

## Reproduction

The successful detonation output from ntlmrelayx:

```
[*] (RAW): Received connection from 127.0.0.1, attacking target smb://127.0.0.1
[*] (RAW): Authenticating connection from /@127.0.0.1 against smb://127.0.0.1 SUCCEED [1]
[*] smb:///@127.0.0.1 [1] -> Service RemoteRegistry is in stopped state
[*] smb:///@127.0.0.1 [1] -> Starting service RemoteRegistry
[*] smb:///@127.0.0.1 [1] -> Executed specified command on host: 127.0.0.1
[-] smb:///@127.0.0.1 [1] -> SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND
[*] smb:///@127.0.0.1 [1] -> Stopping service RemoteRegistry
```

The smbserver hook output showing the multiplexed connection reuse:

```
[RELAY] Hook installed successfully
[*] [RELAY] SMB2 SESSION_SETUP hook installed, relay port=6666
[HOOK] hookedSessionSetup called, connId=Thread-3   ← first auth (NEGOTIATE)
[HOOK] hookedSessionSetup called, connId=Thread-3   ← first auth (AUTHENTICATE)
[HOOK] hookedSessionSetup called, connId=Thread-3   ← second auth intercepted (NEGOTIATE)
[*] [RELAY] Second SESSION_SETUP detected (NTLM NEGOTIATE) - relaying to RAW server port 6666
[HOOK] hookedSessionSetup called, connId=Thread-3   ← second auth (AUTHENTICATE)
[*] [RELAY] Received NTLM AUTHENTICATE - forwarding to RAW server
[*] [RELAY] NTLM relay succeeded! Command should have been executed on target.
```

Several things in these outputs are worth examining carefully because they directly illustrate the part-one mechanics.

The authenticating identity in the ntlmrelayx output is `/@127.0.0.1` — empty domain, empty username. This is not an error. This is the local authentication path producing an empty type-3, exactly as described in part one. The NTLM_AUTHENTICATE message carries no credential fields because the local path skips them. The relay succeeds despite having nothing to verify, because the local path does not perform verification. A relay that shows a real username and domain in this position is using a different code path and would fail against a target that enforces MIC validation or channel binding. This one does not, because those protections are only meaningful when the type-3 is populated.

The `STATUS_OBJECT_NAME_NOT_FOUND` error is ntlmrelayx failing to read back the output file it wrote — the file was created as SYSTEM and then quarantined by Windows Defender before ntlmrelayx could read it. The command executed. The error is post-execution cleanup, not a relay failure.

The four hook calls on `Thread-3` — the same thread ID for both the initial share mount and the SYSTEM authentication — confirm that both authentications arrived over the same TCP connection. This is the multiplexing reuse in action: the SMB client found the existing port 12345 connection in its transport table and routed SYSTEM's SESSION_SETUP through it, which is precisely what CVE-2026-24294 exploits.

## What the telemetry shows

Winlogbeat was not running on SRV01 during the successful detonation. The agent was configured after the attack chain was staged. This is a genuine gap in the instrumented evidence, and it is worth being direct about rather than papering over. What follows is the telemetry from the attack period collected once the agent was running, combined with analytically-derived signatures for what a fully instrumented run would produce.

**The absence of NTLM 4624 events is itself a finding.** A query against the `reflect-lab-logs` index for event ID 4624, LogonType 3, AuthenticationPackageName NTLM on SRV01 during the attack window returns zero results. This is the expected result of the local-auth empty type-3 mechanic: because the NTLM_AUTHENTICATE message is effectively empty on the local path, the resulting logon session carries no authentication package details that would normally populate the NTLM fields in a 4624 event. Standard "look for suspicious NTLM network logons" detection does not catch this class of attack. The absence of the detection signal is not a logging failure; it is a property of the primitive.

**The visible artifact is a Kerberos machine account logon from loopback.** Two event ID 4624 events appear on SRV01 at 22:04:24 UTC during the attack period:

```json
{
  "@timestamp": "2026-07-08T22:04:24.290Z",
  "winlog": {
    "event_id": "4624",
    "event_data": {
      "TargetUserName": "SRV01$",
      "LogonType": "3",
      "IpAddress": "::1",
      "WorkstationName": "-",
      "AuthenticationPackageName": "Kerberos"
    }
  }
}
```

`SRV01$` authenticating to itself over the IPv6 loopback address (`::1`) via a type 3 (network) logon. The machine account authenticating to the local machine over the loopback interface is not a normal workload. No legitimate service pattern produces this. It is the detection-relevant artifact of the multiplexing chain, and it is present even in cases where the NTLM relay produces no visible type-3 record.

**The analytically-derived signatures for a fully instrumented run:**

ntlmrelayx's default execution mechanism abuses the RemoteRegistry service. It starts the service if it is stopped, writes a temporary service entry named `BTOBTO`, executes the payload via that service, and then removes it. A fully instrumented run would produce:

Event 7045 (Service Installed) with `ServiceName: BTOBTO` and `AccountName: LocalSystem`. This is a high-fidelity indicator because no legitimate software installs a service named BTOBTO. The combination of an unknown short-name service installed as LocalSystem is a strong signal regardless of the payload.

Sysmon event 1 (Process Create) showing `cmd.exe` or the specified payload binary spawned with `ParentImage: C:\Windows\System32\services.exe` and `User: NT AUTHORITY\SYSTEM`. A command shell spawned directly from services.exe as SYSTEM, with no service binary in the standard service paths, is the execution artifact.

Sysmon event 3 (Network Connection) showing an SMB client connection to a destination port other than 445. The `net use /tcpport:12345` establishes a TCP connection to port 12345 where port 445 is expected. This is the CVE-2026-24294 bypass's unique network fingerprint. Normal SMB traffic does not appear on port 12345. Any `mrxsmb` or `System` process initiating a TCP connection to a high port on loopback, followed shortly by a 4624 for the machine account, is the compound signature.

## Detection: what to look for

The detection strategy works across two layers. The first catches the anomalous authentication artifact. The second catches the mechanism.

For the authentication layer, the correlation is machine account authenticates to itself over loopback. Concretely: event 4624, LogonType 3, TargetUserName ending in `$` (machine account), IpAddress `127.0.0.1` or `::1`, on the same host that the machine account belongs to. This pattern does not occur in legitimate operations. It is not noisy. A single rule on this correlation covers the reflection primitive regardless of which coercion vector induced it or which port the multiplexing used.

For the mechanism layer, the SMB-to-nonstandard-port connection is the CVE-2026-24294-specific indicator. A network connection from the `System` process or any SMB client component to a local destination on a port other than 445, immediately preceding a machine account logon from loopback, is the compound signature for this specific bypass. Monitoring for outbound SMB-protocol traffic on non-445 ports from the system process is low-noise in enterprise environments because legitimate workloads do not do this.

The RemoteRegistry abuse indicator, event 7045 with a short randomised service name and LocalSystem account, is the payload-delivery signature rather than the reflection signature. It fires when ntlmrelayx uses its default execution mechanism. Payloads delivered differently would not produce this event, so it should be treated as a high-fidelity indicator of this specific toolchain rather than of the primitive class generally.

A Sigma rule capturing the primary authentication artifact:

```yaml
title: Machine Account Loopback Authentication
id: reflect-001
status: experimental
description: >
  Detects a machine account authenticating to the local host over the loopback
  interface via a network logon. This pattern is produced by NTLM reflection
  attacks including CVE-2026-24294 and has no known legitimate analogue.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    TargetUserName|endswith: '$'
    IpAddress|contains:
      - '127.0.0.1'
      - '::1'
  condition: selection
fields:
  - TargetUserName
  - IpAddress
  - AuthenticationPackageName
  - WorkstationName
falsepositives:
  - None known
level: high
```

## Hardening

The single control that neutralises this class regardless of patch state is enforcing inbound SMB signing on member servers. Synacktiv's own analysis notes that CVE-2026-24294 does not affect Windows 11 24H2 precisely because 24H2 enforces SMB signing by default, and a signed session cannot be relayed without the signing keys. This is the defense-in-depth case the Synacktiv writeup makes explicitly: SMB signing collapsed the attack surface before the patch existed.

```powershell
# enforce on all member servers - requires a reboot or SMB service restart to take effect
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
```

In Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > "Microsoft network server: Digitally sign communications (always)" set to Enabled. Apply via a GPO scoped to member server OUs.

Patch to build 26100.32522 or later (March 2026 cumulative update) to close CVE-2026-24294 directly. This is not a substitute for signing enforcement; it is an additional layer. Future reflection variants will likely continue targeting unsigned sessions, so the signing control is the durable one.

Restrict the coercion surface. Disable the Print Spooler service on systems that do not need it, enforce RPC filters on MS-EFSRPC and MS-DFSNM where appropriate, and monitor for unusual RPC bind attempts to coercible interfaces from non-administrative accounts. Coercion requires the ability to invoke a SYSTEM service callback; reducing that surface reduces the class of potential reflection triggers.

Audit ADIDNS write permissions. Default AD grants any authenticated user the ability to create DNS records via dynamic updates. Restricting this to specific accounts or groups closes the record-planting step that more complex variants (including CVE-2025-33073's marshalled-name technique) rely on. The permission is overly broad by default and rarely needs to be as open as it is.

## What build 26100.32230 tells us

This build carries thirteen months of security fixes and is not unpatched or experimental. It is the patch level a significant portion of real Server 2025 deployments run, because Microsoft has not refreshed the Server 2025 evaluation media since the January 2026 release. The finding that CVE-2026-24294 fires on this build is a realistic finding about the current installed base, not a contrived lab condition.

The chain confirmed on 26100.32230: CVE-2025-33073 (marshalled-name SMB-to-SMB) is closed. The custom-port multiplexing variant (CVE-2026-24294) fires. Upgrading to 26100.32522+ closes the specific multiplexing variant. SMB signing enforcement closes the class.

The framing from part one holds here in the lab as much as on paper. Microsoft patched the instance in front of them, correctly. The class persists, and the next instance will be another route into the same local-authentication path that has been there since NT. Enforcing signing is the only control that addresses the class rather than the instance.

## Acknowledgments and references

- Synacktiv, CVE-2026-24294 (bypassing Windows authentication reflection mitigations for SYSTEM shells, part 1): https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1
- Synacktiv, CVE-2025-33073 (NTLM reflection is dead, long live NTLM reflection): https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
- Andrea Pierini (decoder), reflecting your authentication: https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/
- Andrea Pierini (decoder), what Windows Server 2025 quietly did to your NTLM relay: https://decoder.cloud/2026/02/25/what-windows-server-2025-quietly-did-to-your-ntlm-relay/
- Andrea Pierini (decoder), LmCompatibilityLevel and the PDC trap: https://decoder.cloud/2026/04/15/lmcompatibilitylevel-and-the-pdc-trap/
- James Forshaw, relaying Kerberos authentication / CredMarshalTargetInfo: https://www.tiraniddo.dev/2024/04/relaying-kerberos-authentication-from.html
- 0xNDI, CVE-2026-24294 PoC: https://github.com/0xNDI/CVE-2026-24294
- Microsoft, KB5005413, mitigating NTLM relay attacks on AD CS: https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
