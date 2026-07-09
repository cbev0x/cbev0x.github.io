---
title: "Impel: Mapping the RPC Coercion Surface on Windows Server 2025"
date: 2026-07-09
categories: [Personal, Research, Tooling]
tags: [Windows, Active Directory, Coercion, Privilege Escalation, Research]
published: true
---

This post covers **Impel**, a Linux-native RPC coercion surface scanner we built as the final tool in our Windows authentication coercion research series. The previous installments documented the reflection and relay classes in detail, covering CVE-2026-24294 and CVE-2025-33073 with full lab detonation against Windows Server 2025 defaults. Impel maps the upstream surface those techniques depend on: which RPC interfaces are reachable, which coerce authentication outbound, and what that means for defenders trying to shrink the attack surface.

The tool is available at [github.com/cbev0x/impel](https://github.com/cbev0x/impel).

---

## Why a Dedicated Tool

Most coercion scanning today is done either through Coercer (which tries every known method against a target) or through ad-hoc impacket scripting. Neither gives you the full picture in a defensible format. We wanted a tool that does three things none of the existing options do cleanly: distinguish between an interface being *present*, *present but patched*, and *present and exploitable*; generate ready-to-deploy mitigations based on what it actually finds; and serve as a research harness for hunting undiscovered primitives.

The design follows the same pattern as DeleGator and CS2: Linux-native, impacket-based, enumeration-first, with machine-readable JSON output on stdout and rich terminal output on stderr so the two can be cleanly separated in pipelines.

---

## Architecture

Impel is structured as four subcommands:

**`enum`** fingerprints the coercion surface. For each target it probes a nine-vector knowledge base across all candidate named pipes, attempting to bind each interface UUID. The probe classifies each outcome as `REACHABLE` (bound), `denied` (pipe present, creds rejected), `no-iface` (pipe present but interface not registered), or `absent` (pipe not found). The EFSR multi-pipe behavior is modeled as first-class: all five candidate pipes (`lsarpc`, `efsrpc`, `samr`, `netlogon`, `lsass`) are probed independently, and the output collapses to only the pipes that answer. MS-WSP uses a separate raw SMB pipe open rather than a DCERPC bind, since the Windows Search Protocol is a binary framing protocol with no UUID-based endpoint registration.

**`validate`** fires a coercion trigger at a listener you control and confirms the connectback. Eight triggers are implemented: MS-RPRN, MS-PAR, MS-EVEN, MS-EVEN6, MS-EFSR, MS-DFSNM, MS-FSRVP, and MS-WSP. The built-in listener detects the inbound connection and fingerprints it as SMB or HTTP from the first 16 bytes, then drops the socket. It never completes NTLM negotiation and never reads or emits a hash. The listener confirms that coercion happened; if you want the actual net-NTLMv2 material for a writeup, `--external` fires the trigger into your own Responder or ntlmrelayx. The separation is deliberate. impel is a surface assessment tool, not a relay tool.

**`defend`** takes enum output and generates per-host mitigations. It produces a rich report with PowerShell remediation commands, operational context (for example, MS-RPRN and MS-PAR share `\pipe\spoolss` so disabling the Spooler covers both), and two file outputs: a `netsh rpc filter` script that blocks each reachable interface UUID on the `um` layer, and a set of Sigma YAML rules covering Sysmon 18 (named pipe connection), Sysmon 3 (outbound network connection), and Security 4624 (machine account logon) for each detected vector family.

**`research`** implements the novel-primitive discovery methodology. `research dump` queries the endpoint mapper on port 135 and dumps every registered interface with UUID, version, protocol, endpoint, and annotation, cross-referenced against the impel vector DB and impacket's KNOWN_UUIDS. `research flag` applies a scoring heuristic to surface candidates (unknown UUID on a named pipe scores highest; annotation keyword matches add weight). `research probe` binds a user-specified interface and fires each opnum in a range with a UNC parameter pointing at a listener, logging which opnums produce a connectback.

---

## The Vector Knowledge Base

The nine vectors in impel's knowledge base map to the established coercion research corpus:

| Key | Family | Interface | Coercion Method |
|---|---|---|---|
| MS-RPRN | PrinterBug | `12345678-1234-ABCD-EF00-0123456789AB` | `RpcRemoteFindFirstPrinterChangeNotificationEx` |
| MS-PAR | PrinterBug (async) | `76F03F96-CDFD-44FC-A22C-64950A001209` | `RpcAsyncOpenPrinter` |
| MS-EFSR | PetitPotam | `c681d488-d850-11d0-8c52-00c04fd90f7e` | `EfsRpcOpenFileRaw` (multi-pipe) |
| MS-EFSR-alt | PetitPotam | `df1941c5-fe89-4e79-bf10-463657acf44d` | `EfsRpcOpenFileRaw` |
| MS-DFSNM | DFSCoerce | `4fc742e0-4a10-11cf-8273-00aa004ae673` | `NetrDfsRemoveStdRoot` |
| MS-FSRVP | ShadowCoerce | `a8e0653c-2744-4389-a61d-7373df8b2292` | `IsPathShadowCopied` |
| MS-EVEN | EventLog coercion | `82273fdc-e32a-18c3-3f78-827929dc23ea` | `ElfrOpenBELW` |
| MS-EVEN6 | EventLog coercion v6 | `f6beaff7-1e19-4fbb-9f8f-b89e2018337c` | `EvtRpcOpenLogHandle` |
| MS-WSP | WSPCoerce | `bad611b0-158a-4a44-b0ad-42fbdbab0d5d` | `CPMCreateQueryIn` |

A few implementation notes worth documenting. MS-PAR's coercion primitive is a single `RpcAsyncOpenPrinter` call (opnum 0) whose `pPrinterName` parameter is a UNC pointing at the listener. There is no async find-first equivalent; the async protocol handles printer change notifications differently from MS-RPRN. MS-FSRVP requires a `GetSupportedVersion` / `SetContext(FSRVP_CTX_BACKUP)` handshake before `IsPathShadowCopied`, but the handshake response bytes must be consumed on a separate connection. If you fire the handshake and the coercion call on the same DCE context, the unread response bytes from `GetSupportedVersion` desynchronise the protocol state and the server disconnects with `STATUS_PIPE_DISCONNECTED`. impel handles this by disconnecting and rebinding after the handshake. MS-WSP is not DCERPC at all. It uses a binary framing protocol over `\pipe\MsFteWds` driven via `FSCTL_PIPE_TRANSCEIVE` ioctls; the packet builders are adapted from RedTeam Pentesting's wspcoerce.

---

## Lab Setup

We validated everything in reflect.lab, a three-host Windows Server 2025 domain:

- **DC01** (domain controller, DFS enabled)
- **SRV01** (file server, FS-VSS-Agent and Windows Search installed for FSRVP/WSP coverage)
- **SRV02** (AD CS / IIS, clean baseline)

All machines are fully patched Windows Server 2025 (build 26100) as of the time of writing.

---

## Empirical Findings: Windows Server 2025 Default Surface

The following table summarises every vector we tested across the reflect.lab fleet. The validate column reflects results with lowpriv domain user credentials unless noted.

| Vector | enum status | validate result | Notes |
|---|---|---|---|
| MS-DFSNM | REACHABLE (DC01 only) | **COERCED** | No CVE, unpatched, domain user sufficient |
| MS-WSP | DENIED (SRV01) | **COERCED** (admin) | Pipe ACL restricts to admin; Windows Search off by default on Server 2025 |
| MS-EFSR | no-iface (all) | n/a | Interface UUID not registered on any pipe |
| MS-EFSR-alt | no-iface (all) | n/a | Same |
| MS-FSRVP | REACHABLE (SRV01) | access_denied | CVE-2022-30154; service-level security callback |
| MS-EVEN | REACHABLE (all) | fires, no coercion | Server 2025 removed outbound auth from EventLog service |
| MS-EVEN6 | REACHABLE (all) | fires, no coercion | Same |
| MS-RPRN | absent (all) | n/a | `\pipe\spoolss` not exposed remotely by default |
| MS-PAR | absent (all) | n/a | Same pipe, same restriction |

### MS-DFSNM (DFSCoerce)

`NetrDfsRemoveStdRoot` on `\pipe\netdfs` coerced DC01 immediately with lowpriv credentials. This is the only vector that works out of the box against a fully patched Windows Server 2025 domain controller with default settings. Microsoft has not assigned a CVE and has stated they do not plan to patch authenticated coercion issues of this class. The recommended mitigation is an RPC filter blocking the DFSNM interface UUID on the `um` layer, or disabling the DFS Namespace service if DFS is not in use.

```
DC01.reflect.lab  MS-DFSNM  NetrDfsRemoveStdRoot  fired=true  coerced=true
connectback: 10.10.10.10:50024/smb
```

### MS-WSP (WSPCoerce)

`CPMCreateQueryIn` with a `file:////10.10.10.50/impel` scope coerced SRV01 with Administrator credentials. The Windows Search service exposes `\pipe\MsFteWds` but restricts pipe access to administrative accounts at the SMB layer: lowpriv receives `STATUS_ACCESS_DENIED` on the `createFile` call before we send a single WSP message. This makes WSPCoerce a post-escalation vector on Server 2025, not a low-priv primitive. The Windows Search service is disabled by default on Server 2025; the vector only applies to servers where it has been explicitly enabled.

```
SRV01.reflect.lab  MS-WSP  CPMCreateQueryIn  fired=true  coerced=true
connectback: 10.10.10.11:57402/smb
```

### MS-EFSR (PetitPotam)

Every candidate pipe answered the SMB open and accepted a DCERPC connection, but the EFSR interface UUID (`c681d488`) was not registered on any of them. The bind returns `abstract_syntax_not_supported` across all five pipes: `lsarpc`, `efsrpc`, `samr`, `netlogon`, and `lsass`. The interface registration has been removed entirely from Windows Server 2025, not just restricted. CVE-2021-36942 (August 2021) patched the unauthenticated `EfsRpcOpenFileRaw` vector, and subsequent rollups completed the removal of the interface from the endpoint registration. The `efsrpc` named pipe no longer exists on patched Server 2025 hosts.

impel correctly reports `no-iface` rather than `absent` for this vector. The distinction matters for blue teams: the pipes are present and the transport is accessible, but the coercion surface is gone at the interface layer.

### MS-FSRVP (ShadowCoerce)

The `FssagentRpc` pipe bound successfully on SRV01 (FS-VSS-Agent role installed), and the `GetSupportedVersion` / `SetContext` handshake completed. `IsPathShadowCopied` fired with the listener UNC as `ShareName`. The call returned `rpc_s_access_denied` with zero connectback, even when retried with Administrator credentials and with the caller added to the Backup Operators group.

Microsoft confirmed that ShadowCoerce was mitigated as part of CVE-2022-30154 in June 2022. The mitigation operates as a security callback in the fssagent service that validates the call at the RPC security layer before any parameter processing, which is why neither elevated credentials nor group membership changes the result. Windows Server 2025 ships with this patch, so the surface is present (bindable, interface registered) but the coercion primitive is dead.

### MS-EVEN and MS-EVEN6

Both interfaces bound on `\pipe\eventlog` across all three hosts, and both triggers dispatched their respective methods (`ElfrOpenBELW` for EVEN, `EvtRpcOpenLogHandle` for EVEN6). Neither produced a connectback even after extending the wait to 20 seconds. The EventLog service on Server 2025 accepts these calls but does not resolve the UNC path outbound. We did not find a specific CVE for this change; it appears to be part of the broader service-level outbound auth removal Microsoft applied across the coercion corpus in the Server 2022/2025 generation.

We had not confirmed MS-EVEN6 as a reliable coercion primitive before this lab run. The EPM dump showed it registered on `\pipe\eventlog` (annotation: "Windows Event Log") across all three hosts, and the interface bound cleanly. The `EvtRpcOpenLogHandle` method accepts a `Channel` parameter which takes a UNC path, but the outbound auth behaviour is patched the same way as EVEN. MS-EVEN6 is confirmed present on Server 2025 but non-coercible in the default patched state.

### MS-RPRN and MS-PAR (PrinterBug)

The Print Spooler service was running on all three hosts, but `enum` reported `absent` for both vectors. The named pipe `\pipe\spoolss` is not exposed over SMB by default on Windows Server 2025 regardless of credential level. Setting `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RegisterSpoolerRemoteRpcEndPoint = 1` enables the remote pipe, but the change requires a full system reboot to take effect, not just a service restart.

The EPM dump produced one additional finding here. Both RPRN (`12345678-1234-ABCD-EF00-0123456789AB`) and PAR (`76F03F96-CDFD-44FC-A22C-64950A001209`) are still registered with the endpoint mapper on TCP port 49672. The TCP bind succeeds with lowpriv credentials. However, `RpcOpenPrinter` called over the TCP transport returns `rpc_s_cannot_support` (0x6E4) before the coercion method is reached. The spooler enforces transport-level method restrictions independently of the pipe gating, so both layers need to be present for the vector to work. The TCP registration without a working named pipe is not an exploitable gap, but it is worth noting: a scanner that only checks EPM registration would report RPRN and PAR as present when the actual attack surface is blocked.

PrinterBug has no CVE assigned and Microsoft considers it a design-level won't-fix. The Server 2025 change is a hardening default, not a protocol-level patch. With the registry key and a reboot the pipe reappears and the vector likely coerces, which we were unable to confirm due to lab stability constraints.

---

## Defend: From Surface to Script

Running `defend` against the enum output produces per-host output in under a second:

```bash
python3 -m impel enum DC01.reflect.lab SRV01.reflect.lab SRV02.reflect.lab \
    -u lowpriv -p 'Lab1234!' -d reflect.lab --json | \
    python3 -m impel defend --from-json - \
    --netsh ./filters/ --sigma ./sigma/
```

The generated netsh scripts contain clean block rules with no comment lines (netsh has no comment syntax; any non-command line in a `-f` script generates an error):

```
rpc filter
add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=4fc742e0-4a10-11cf-8273-00aa004ae673
add filter

add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=82273fdc-e32a-18c3-3f78-827929dc23ea
add filter

add rule layer=um actiontype=block
add condition field=if_uuid matchtype=equal data=f6beaff7-1e19-4fbb-9f8f-b89e2018337c
add filter

quit
```

Applied with `netsh -f filter.txt`. After applying the DC01 script, we reran `validate` against the three blocked vectors. All three returned `rpc_s_access_denied` with zero connectback:

```
DC01  MS-DFSNM  NetrDfsRemoveStdRoot  fired=true  coerced=false  rpc_s_access_denied
DC01  MS-EVEN   ElfrOpenBELW          fired=true  coerced=false  rpc_s_access_denied
DC01  MS-EVEN6  EvtRpcOpenLogHandle   fired=true  coerced=false  rpc_s_access_denied
```

One operational note: `enum` continues to show these vectors as `REACHABLE` even with filters applied. The `enum` probe is a bind test only; the RPC filter fires on the `um` layer at method invocation, not at bind time. A bind-only scanner will show filtered interfaces as accessible because the filter never triggers during a bind. `validate` is the authoritative ground truth for coercibility.

MS-WSP is excluded from the netsh scripts intentionally. The Windows Search Protocol is not DCERPC and has no UUID-based endpoint registration on the `um` layer. The correct mitigation is service disablement (`Stop-Service WSearch; Set-Service WSearch -StartupType Disabled`), which `defend` documents in the per-vector output alongside the script.

---

## Research: EPM Dump and Primitive Hunting

`research dump` against DC01 returned 190 registered interfaces across `ncacn_np`, `ncacn_ip_tcp`, `ncacn_http`, and `ncalrpc` transports. Known coercion vectors are flagged in the output:

```
12345678-1234-abcd-ef00-0123456789ab  1.0  ncacn_ip_tcp  49672  ⚑ COERCION MS-RPRN (PrinterBug)
76f03f96-cdfd-44fc-a22c-64950a001209  1.0  ncacn_ip_tcp  49672  ⚑ COERCION MS-PAR (PrinterBug (async))
f6beaff7-1e19-4fbb-9f8f-b89e2018337c  1.0  ncacn_np     \pipe\eventlog  ⚑ COERCION MS-EVEN6
```

`research flag` applies a scoring heuristic: known coercion vector on a named pipe scores highest, unknown UUID on a named pipe scores second, annotation keyword matches (file, path, share, backup, log, search) add weight. We probed the top unknown candidates with `research probe`, which fires each opnum with a WSTR UNC parameter and waits for a connectback.

The result across all unknown interfaces in the EPM dump was uniform `rpc_s_access_denied` regardless of opnum and regardless of whether we used lowpriv or Administrator credentials. This is not a null result. It is a finding about Server 2025's security architecture.

Every probed interface on this DC enforces a security callback that rejects remote callers before any parameter processing, without exception. The single interface that does not enforce this pattern is MS-DFSNM. That is precisely why DFSCoerce still works when everything else is patched: the DFS Namespace service was not updated to implement the RPC security callback pattern that Microsoft systematically applied to the rest of the coercion corpus in the Server 2022/2025 generation. The research methodology does not discover a new primitive here, but it does demonstrate why the existing one survives.

---

## Usage Reference

```bash
# Install
pip install impacket rich

# Enumerate coercion surface
python3 -m impel enum DC01.reflect.lab -u user -p 'pass' -d domain.lab

# Validate with built-in listener (needs root for :445)
sudo python3 -m impel validate DC01.reflect.lab -L 10.10.10.50 \
    --vector MS-DFSNM -u user -p 'pass' -d domain.lab

# Use your own Responder instead
python3 -m impel validate DC01.reflect.lab -L 10.10.10.50 \
    --vector MS-DFSNM --external -u user -p 'pass' -d domain.lab

# Generate mitigations, netsh scripts, and Sigma rules
python3 -m impel enum ... --json | \
    python3 -m impel defend --from-json - --netsh ./filters/ --sigma ./sigma/

# EPM dump and candidate flagging
python3 -m impel research dump DC01.reflect.lab
python3 -m impel research flag DC01.reflect.lab

# Probe a candidate interface for coercion
sudo python3 -m impel research probe DC01.reflect.lab \
    --uuid <UUID> --pipe <pipe> --opnums 0-20 \
    -L 10.10.10.50 -u user -p 'pass' -d domain.lab
```

Human output goes to stderr. `--json` output goes to stdout. Exit code `0` means coercion surface found or coercion confirmed; `1` means nothing found; `2` means usage error.

---

## Conclusion

On a fully patched Windows Server 2025 domain, two coercion primitives survive in the default configuration: MS-DFSNM (DFSCoerce) with domain user credentials, and MS-WSP (WSPCoerce) with administrative access. Every other vector in the established corpus is patched, gated by default, or blocked at the service level. The mitigation is defence in depth: disable the DFS Namespace service if it is not required, apply the RPC filter if it is, and disable Windows Search on servers where indexing has no operational purpose.

The code is on GitHub. Feedback, bug reports, and additional vector submissions welcome.

---

## References and Acknowledgements

**CVEs and advisories**

- CVE-2021-36942 — Windows LSA Spoofing Vulnerability (PetitPotam / MS-EFSR). Microsoft, August 2021.
- CVE-2022-26925 — Windows LSA Spoofing Vulnerability (PetitPotam variant). Microsoft, May 2022.
- CVE-2022-30154 — MS-FSRVP coercion (ShadowCoerce). Microsoft, June 2022.
- KB5005413 — Mitigating NTLM Relay Attacks on Active Directory Certificate Services. Microsoft.

**Prior coercion research this tool builds on**

- Gilles Lionel ([@topotam77](https://twitter.com/topotam77)) — PetitPotam / MS-EFSR coercion. Original PoC: [github.com/topotam/PetitPotam](https://github.com/topotam/PetitPotam)
- Filip Dragovic ([@Wh04m1001](https://twitter.com/Wh04m1001)) — DFSCoerce / MS-DFSNM. Original PoC: [github.com/Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce)
- Gilles Lionel — ShadowCoerce / MS-FSRVP. PoC: [github.com/ShutdownRepo/ShadowCoerce](https://github.com/ShutdownRepo/ShadowCoerce)
- Lee Christensen ([@tifkin_](https://twitter.com/tifkin_)) and Elad Shamir — PrinterBug / MS-RPRN original research.
- Charlie Clark ([@exploitph](https://twitter.com/exploitph)) — additional coercion primitive research.
- p0dalirius — Coercer tool and the systematic enumeration of coercion-capable RPC methods across the MS-* protocol corpus: [github.com/p0dalirius/Coercer](https://github.com/p0dalirius/Coercer)
- RedTeam Pentesting GmbH — WSPCoerce, the Python/impacket implementation of MS-WSP coercion whose packet builders are adapted in impel's `wsp_packets.py`: [github.com/RedTeamPentesting/wspcoerce](https://github.com/RedTeamPentesting/wspcoerce)

**RPC internals and filter mechanics**

- James Forshaw ([@tiraniddo](https://twitter.com/tiraniddo)) — "How the Windows Firewall RPC Filter Works", Tyranid's Lair, August 2021. The analysis of how `layer=um` enforcement operates at the security callback level rather than the bind level directly informed the `validate`-after-filter design in impel's defend module.
- Akamai Security Research — "A Definitive Guide to the Remote Procedure Call (RPC) Filter", October 2024.

**Prior work in this series**

- Part 1: Windows NTLM Authentication Reflection — CVE-2026-24294
- Part 2: Coercion-to-Relay Attack Chains on Windows Server 2025 Defaults
- Part 3: AD CS / ESC8 Relay with Extended Protection for Authentication

**Tool dependencies**

- [Impacket](https://github.com/fortra/impacket) — the RPC transport, NDR, and SMB layers that impel is built on throughout.
- [Rich](https://github.com/Textualize/rich) — terminal output rendering.
