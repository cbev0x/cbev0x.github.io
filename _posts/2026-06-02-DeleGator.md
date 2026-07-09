---
title: "DeleGator: Building and Testing a Linux-Native Kerberos Delegation Abuse Framework"
date: 2026-06-02
categories: [Personal, Research, Tooling]
tags: [Windows, Active Directory, Delegation, Privilege Escalation]
published: true
---

This writeup covers the development, architecture, and OPSEC testing of DeleGator — a Linux-native Active Directory delegation abuse framework. It is split into three parts: a technical overview of what the tool does and how it works, documentation of the lab environment built to test it, and measured OPSEC data from real test runs against that environment with Elastic SIEM detection in place.

The tool is available at [github.com/cbev0x/DeleGator](https://github.com/cbev0x/DeleGator).

---

# Part One: Tool Overview and Capabilities

## What is DeleGator?

DeleGator is a Linux-native Active Directory delegation abuse framework built to bridge the gap between enumeration and exploitation. The problem it solves is a practical one — most tooling in this space is either enumeration-only or exploitation-only, leaving the operator to manually correlate findings, determine which attack path applies, and then switch between multiple scripts to execute it. DeleGator handles all three phases in a single tool: it enumerates delegation misconfigurations, identifies exploitable attack chains automatically, and executes the full Kerberos exploitation chain from a single command.

It was built with a specific operational philosophy: every claim about OPSEC noise is backed by measured Windows event data from a real AD lab with Elastic SIEM detection running throughout development, not assumptions.

---

## Delegation Attack Coverage

Active Directory supports three delegation models, each with distinct exploitation paths. DeleGator covers all three.

### Unconstrained Delegation

The oldest and noisiest delegation type. When a computer account has `TRUSTED_FOR_DELEGATION` set in its `userAccountControl` attribute, any user who authenticates to a service on that machine has their TGT automatically forwarded to it. An attacker with a position to coerce a privileged machine into authenticating to the target can capture that forwarded TGT and use it for further attacks including DCSync.

DeleGator enumerates unconstrained delegation targets, checks their reachability, identifies which coercion techniques are likely viable against each target (SpoolSS/PrinterBug, PetitPotam, DFSCoerce), generates the exact commands to run the attack with the appropriate listener setup, and monitors for captured ccache files automatically when `--watch` is specified.

### Constrained Delegation

A more targeted delegation model configured via `msDS-AllowedToDelegateTo`. DeleGator handles both exploitation variants, which differ significantly and are often treated identically by other tools:

**With protocol transition** — The service account has `TRUSTED_TO_AUTH_FOR_DELEGATION` set, meaning it can invoke S4U2Self to obtain a forwardable service ticket on behalf of any user without needing that user's credentials. This is the most commonly encountered and most exploitable variant. DeleGator performs S4U2Self followed by S4U2Proxy in a single operation, writes the resulting ccache to disk, and prints the exact commands to use it.

**Without protocol transition** — S4U2Self alone cannot produce a forwardable ticket for arbitrary users. The operator must supply an existing ccache for the target user, which DeleGator then uses as the `additionalTicket` in the S4U2Proxy TGS-REQ. DeleGator auto-detects which path applies by querying the account's `userAccountControl` attribute and routes accordingly, with the option to override manually.

### Resource-Based Constrained Delegation (RBCD)

The most commonly encountered delegation attack in modern environments. RBCD abuse begins with a write permission — specifically `GenericWrite`, `WriteDacl`, `WriteOwner`, or `GenericAll` — over a computer object. The attacker writes a crafted security descriptor to `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target, granting a controlled account delegation rights over it, then executes the S4U2Self and S4U2Proxy chain to obtain a service ticket as a privileged user.

DeleGator handles the full chain: verifying write access, resolving the delegation account SID, constructing the correct binary security descriptor using the same `impacket.ldap.ldaptypes` primitives as the authoritative impacket reference implementation, writing the RBCD attribute via LDAP, executing the S4U chain, writing the ccache to disk, and optionally cleaning up the attribute afterward with `--cleanup`.

---

## Enumeration and Attack Path Correlation

The enumeration module is what separates DeleGator from a collection of exploitation scripts. Rather than returning raw LDAP attribute dumps, it correlates individual findings into actionable attack chains.

All enumeration uses targeted LDAP filters rather than broad directory dumps. Each query is scoped precisely to the attributes needed — for example, unconstrained delegation enumeration uses a filter for `TRUSTED_FOR_DELEGATION` while explicitly excluding domain controllers, which legitimately carry that flag and would otherwise produce false positives in every other tool that performs this check.

The correlation engine examines findings across all three delegation types simultaneously. A low-privileged user with `GenericWrite` over a computer that has constrained delegation to a high-value SPN produces a chained attack path surfaced as a single `CRITICAL` finding rather than two separate unrelated findings. Attack paths are ranked by severity and presented with the complete exploitation steps, making the output immediately actionable rather than requiring the operator to reason about the relationship between findings manually.

---

## Authentication Methods

DeleGator supports four authentication methods across all modules, accepting exactly one per invocation:

**Password** — standard plaintext credential, used for direct authentication.

**NTLM hash** — accepts `LM:NT`, `:NT` (colon-prefixed), or bare NT hash formats. Supports pass-the-hash for both LDAP binding and Kerberos TGT acquisition.

**Kerberos ccache** — accepts an explicit file path or reads `KRB5CCNAME` from the environment automatically. Skips the AS-REQ entirely when used for TGT-dependent operations, reducing KDC event noise to only the S4U requests. Requires `gssapi` for LDAP binding.

**Certificate (PKINIT)** — accepts PFX/PKCS12 files with optional decryption password, or separate PEM certificate and key files. Enables certificate-based Kerberos pre-authentication for environments where ADCS has been leveraged to obtain user certificates.

---

## OPSEC Design

OPSEC awareness is built into the tool's architecture rather than added as an afterthought. Several design decisions directly reduce the detection surface compared to equivalent tools:

Kerberos authentication is preferred over NTLM for all LDAP operations. NTLM authentication against LDAP generates additional logon events and is increasingly flagged by modern detection rules. When a ccache is supplied, the tool avoids the AS-REQ entirely and uses the existing ticket, eliminating the 4768 event that a fresh TGT request would generate.

LDAP queries use tight, specific filters. No broad `(objectClass=*)` style directory dumps are made at any point. The unconstrained delegation filter explicitly excludes domain controllers. The RBCD write path query is scoped to `CN=Computers` rather than the full domain root. Each query type is a separate targeted request rather than a single large pull, keeping per-query event volume low.

Configurable timing controls sit in the LDAP layer. The `--delay` and `--jitter` flags apply to every query, and `--slow` sets a preset that mimics the cadence of legitimate AD management tooling. The `--opsec-check` flag surfaces pre-flight warnings before any operation that generates events above a low noise threshold, showing the operator exactly which Event IDs will be generated before they confirm.

Every operation has a measured noise profile documented in the tool's README and printed in the terminal after each exploit run, showing the exact Event IDs generated and a subjective noise rating based on real measurements from the development lab.

---

## Output and Tool Chaining

The default output is colored terminal output designed to be immediately actionable. After a successful exploitation, the tool prints the ccache path, the exact `export KRB5CCNAME=` command, a ready-to-run NetExec command appropriate for the target service, and the equivalent Impacket command — determined automatically from the target SPN rather than requiring the operator to work it out.

JSON mode (`--json`) outputs a structured findings object suitable for piping into other tools or ingesting into reporting frameworks. The JSON output includes all enumeration findings, the correlated attack paths, and a summary block with counts and severity breakdowns.

The `--out` flag controls the ccache output directory, and ccache filenames are auto-generated in the format `<user>_<service>_<host>_<timestamp>.ccache` to avoid overwriting existing tickets.

---

## Implementation Notes

DeleGator implements S4U2Self and S4U2Proxy from scratch at the ASN.1 and KDC request level, compatible with Impacket 0.13.x. The S4U2Self implementation constructs the `PA-FOR-USER` padata structure following the MS-SFU specification exactly — the checksum is computed as `HMAC-MD5(session_key, usage=17, NT_PRINCIPAL || username || realm || "Kerberos")` in raw bytes matching the getST.py reference implementation. S4U2Proxy uses the `cname_in_addl_tkt` KDC option with `PA-PAC-OPTIONS` containing the `resource_based_constrained_delegation` flag, which is the correct signal for both traditional constrained delegation and RBCD proxy requests.

The RBCD security descriptor is built using `impacket.ldap.ldaptypes` — the same library used by impacket's own `ldapattack.py` — producing the exact binary encoding Windows accepts for `msDS-AllowedToActOnBehalfOfOtherIdentity` writes via LDAP.

---

# Part Two: Lab Environment and Testing Infrastructure

## Overview

Before writing a single line of DeleGator's code, I wanted to make sure every OPSEC claim the tool makes is backed by real, measured data rather than assumptions. Too many offensive tools ship with vague claims about being "low-noise" or "EDR-aware" without any concrete evidence behind them. I didn't want to build another one of those.

To address that, I built an Active Directory lab from scratch with full centralized detection running alongside it. Every DeleGator operation including enumeration queries, S4U requests, and full delegation abuse chains gets tested against this environment before any code is considered stable. What fires, what doesn't, and what the event volume looks like at each step is documented and fed directly back into the tool's design decisions.

The goal wasn't just to have a place to run the tool. It was to have a place to honestly measure it. This section documents what went into building that environment, why each component was chosen, and how the testing process actually works.

---

## Domain Infrastructure

The lab runs a single Active Directory forest (`delegator.lab`) across four Windows machines, each deliberately misconfigured to represent a distinct delegation attack scenario. A fifth Linux machine hosts the detection stack. All machines sit on an isolated host-only VMware network (VMnet10, `192.168.10.0/24`) with no internet exposure during testing to prevent any external noise from polluting the event logs.

|Host|IP|OS|Role|
|---|---|---|---|
|DC01|192.168.10.10|Windows Server 2022|Domain Controller + ADCS Certificate Authority|
|SRV01|192.168.10.20|Windows Server 2019|Unconstrained delegation target|
|SRV02|192.168.10.30|Windows Server 2019|Constrained delegation target (with and without protocol transition)|
|SRV03|192.168.10.40|Windows Server 2019|RBCD target|
|Elastic|192.168.10.50|Ubuntu 24.04 Server|SIEM and detection stack|

The attack box is a standard Kali Linux installation living on a separate network segment (VMnet11, `192.168.20.0/24`) with a second NIC bridging into VMnet10. This topology simulates a realistic internal engagement foothold where the attacker has a presence on the network but is not domain-joined, which is the scenario DeleGator is designed to operate from.

---

## Delegation Configurations

Each member server is configured with a specific delegation type to give the tool a concrete target for each exploitation module. The configurations are intentional and documented so results are reproducible.

**SRV01 - Unconstrained Delegation**

The `SRV01$` computer account has `TRUSTED_FOR_DELEGATION` set in its `userAccountControl` attribute, which is the flag Windows uses to mark a machine as trusted for unconstrained delegation. Any user who authenticates to a service running on this machine will have their TGT forwarded to it automatically, which is what makes unconstrained delegation so dangerous. This is the oldest and noisiest delegation type and is increasingly rare in modern environments, but it still appears in legacy infrastructure and on older machines that have never been audited. The Windows Print Spooler service is also left enabled on SRV01 to support coercion-based TGT capture testing via the PrinterBug and PetitPotam techniques, which are the realistic attack vectors for abusing unconstrained delegation from a remote position.

**SRV02 - Constrained Delegation**

Two service accounts are configured on SRV02 to cover both variants of constrained delegation, since the exploitation path differs significantly between them and most tools treat them identically.

`svc-mssql` has `msDS-AllowedToDelegateTo` populated with `MSSQLSvc/DC01.delegator.lab:1433` and has the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag set, enabling protocol transition. This means the account can invoke S4U2Self to obtain a service ticket on behalf of any user without needing that user's TGT first, then chain directly into S4U2Proxy to delegate to the target SPN. It is the most exploitable constrained delegation configuration and the most commonly encountered.

`svc-http` has constrained delegation configured to `HTTP/SRV02.delegator.lab` but without protocol transition enabled. This variant requires the attacker to already possess a valid TGT for the target user before S4U2Proxy can be invoked, which is a meaningfully different exploitation path that DeleGator surfaces distinctly in its enumeration output rather than lumping both variants together.

**SRV03 - Resource-Based Constrained Delegation**

The low-privileged service account `svc-web` has `GenericWrite` access over the `SRV03$` computer object in Active Directory. The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on SRV03 is initially empty. DeleGator's RBCD exploitation module writes a crafted security descriptor to that attribute as part of the attack chain, which is what configures the delegation relationship and opens the path to S4U2Self and S4U2Proxy. This makes SRV03 a full end-to-end test of the complete RBCD flow: enumerate the write permission, configure the delegation attribute, obtain a service ticket via S4U, and write the resulting ccache to disk.

**DC01 - Certificate Authority**

ADCS is installed on DC01 as an Enterprise Root CA named `delegator-CA`. Beyond supporting certificate-based authentication for DeleGator's auth module, this gives the lab a foundation for future ADCS abuse scenario testing including ESC misconfigurations, which are increasingly relevant in real-world AD assessments.

---

## Service Accounts

The following accounts are configured across the domain. Each one exists for a specific purpose in the testing framework rather than as generic filler accounts.

|Account|Purpose|
|---|---|
|`svc-mssql`|Constrained delegation with protocol transition, SPN registered for MSSQL on DC01|
|`svc-http`|Constrained delegation without protocol transition, HTTP SPN on SRV02|
|`svc-uncon`|Service account associated with the SRV01 unconstrained delegation scenario|
|`svc-web`|Low-privileged account with GenericWrite over SRV03$, used to test RBCD configuration path|
|`htb-user`|Unprivileged domain user with no special permissions, used as the initial foothold account for all testing|

`htb-user` is deliberately kept low-privilege with no group memberships beyond Domain Users. All tool testing is performed authenticating as this account to validate that enumeration and exploitation paths work from a realistic foothold context rather than from an account that already has elevated access.

---

## Detection Stack

The detection layer is what separates this from a standard practice lab. The goal is not just to confirm that attacks work, but to measure exactly what they look like to a defender so that DeleGator's OPSEC design decisions are grounded in real telemetry.

### Elastic SIEM

Elasticsearch 8.x and Kibana run on the Ubuntu node at `192.168.10.50`. Elasticsearch stores and indexes all incoming event data, while Kibana provides the query interface, dashboards, and detection rule engine. Logstash handles the ingest pipeline, listening on port 5044 for Beats input and forwarding normalized events into daily-rolling `winlogbeat-*` indices. The entire stack runs on 6GB of RAM allocated to the Ubuntu VM, which is sufficient for lab-scale event volume without significant indexing lag.

### Winlogbeat

Winlogbeat is deployed on all four Windows machines and ships events from the following channels to Logstash in real time:

- `Security` covering Kerberos ticket events (4768, 4769, 4770), logon events (4624, 4648), directory service access (4662), and directory service changes (5136)
- `System` for service control manager events and driver activity
- `Microsoft-Windows-Sysmon/Operational` for process creation, network connections, and named pipe activity
- `Microsoft-Windows-PowerShell/Operational` for script block logging
- `Microsoft-Windows-WMI-Activity/Operational` for WMI execution events

The Security channel events from DC01 are the most important for measuring Kerberos-related tool activity since the KDC logs all ticket requests and service ticket operations there. Events 4768 and 4769 in particular are what surface S4U2Self and S4U2Proxy requests.

### Sysmon

Sysmon is deployed across all four machines using the Olaf Hartong modular configuration, which is the most comprehensive community-maintained Sysmon config available and goes significantly beyond the commonly used SwiftOnSecurity baseline. It covers process creation with full command line and hashes, network connection events with process context, named pipe creation and connection (relevant for lateral movement detection), LSASS access attempts, DNS query logging, and WMI event subscription activity. On the member servers, Sysmon provides the primary host-level telemetry for measuring what tool operations look like at the process and network layer rather than just the Windows event log layer.

### Audit Policies

Extended audit policies are enabled on all machines beyond the Windows defaults, covering Kerberos Service Ticket Operations, Kerberos Authentication Service, Directory Service Access, Directory Service Changes, Logon and Special Logon events, and Other Object Access Events. Without these policies explicitly enabled, a significant portion of the events needed to measure delegation abuse activity would never be generated. Enabling them across all machines including the member servers rather than just DC01 ensures complete visibility into the full event chain each tool operation produces.

### Detection Rules

Elastic's prebuilt detection rule library is loaded in Kibana's Security module with relevant rule categories enabled covering Kerberos abuse, anomalous ticket requests, LDAP enumeration, DCSync, credential access, privileged object modification, and Active Directory attribute changes.

Two custom detection rules are also configured specifically for DeleGator's primary operation surface:

**RBCD Attribute Modified** fires on Event ID 5136 when `msDS-AllowedToActOnBehalfOfOtherIdentity` is written to any computer object. This is the most direct detection for the RBCD exploitation module and represents the event that a well-tuned SOC would alert on immediately when RBCD is being configured offensively.

**Suspicious S4U Kerberos Request** fires on Event ID 4769 with ticket options matching S4U2Proxy request patterns. This rule benchmarks how visible the Kerberos abuse portion of constrained delegation exploitation is against a monitored environment.

These two rules serve as the primary OPSEC pass/fail benchmarks during development. If a module fires them unnecessarily or with more frequency than expected, the implementation gets revisited before the code is considered stable.

---

## Testing Methodology

For each DeleGator module and operation, the testing process follows a consistent structure to ensure results are comparable across different operations and across tool iterations.

1. Roll back all Windows machines to their base delegation configuration snapshots to ensure a clean event log baseline
2. Execute the target operation from Kali authenticating as `htb-user`
3. Review Kibana Discover immediately afterward, filtering to the relevant time window and host
4. Record which Event IDs were generated, how many times, and from which source
5. Check whether any detection rules fired, noting the rule name and the specific event that triggered it
6. Document everything in a structured results table covering operation, events generated, detection rule hits, and a noise rating

That table is what backs every OPSEC-related statement in DeleGator's documentation. The aim is that anyone reading the README can see exactly what the tool generates under detection and make an informed decision about when and how to use it in a real engagement.

---

## Hypervisor and Hardware

The lab runs entirely on VMware Workstation Pro 17.6.4. All six VMs run simultaneously during active testing sessions with a combined RAM allocation of approximately 23GB against a 32GB host, which leaves comfortable headroom without needing to power machines on and off between tests.

Snapshots are maintained at two points for each machine: the initial delegation configuration baseline taken immediately after setup, and a clean post-testing restore point used between test runs. Rolling back to snapshot rather than manually cleaning up event logs or reversing configuration changes ensures each test run starts from an identical known state, which is what makes the detection measurements reliable and repeatable.

---

_This lab was built from scratch specifically for DeleGator development and OPSEC validation. All testing is performed in an isolated environment against intentionally misconfigured infrastructure with no connection to any production systems._

---

# Part Three: OPSEC Testing and Detection Coverage

## Overview

Every OPSEC claim in DeleGator is backed by measured Windows event data from the lab described in Part Two, with Elastic SIEM and Sysmon detection running throughout testing. This section documents the exact events each operation generates, the detection rules that fired, and the concrete difference OPSEC-aware operational choices make in practice.

All tests were performed against a Windows Server 2022 domain controller with extended audit policies enabled, Sysmon deployed using the Olaf Hartong modular configuration, and Winlogbeat shipping events to Elasticsearch 8.x in real time.

---

## Lab Detection Stack

|Component|Version|Role|
|---|---|---|
|Windows Server 2022|Build 20348|Domain Controller (DC01)|
|Sysmon|15.x|Host telemetry (Olaf Hartong config)|
|Winlogbeat|8.19.0|Event shipping|
|Logstash|8.19.x|Pipeline ingestion|
|Elasticsearch|8.19.x|Event storage and indexing|
|Kibana|8.19.x|Detection rules and query interface|

Audit policies enabled on all machines:

- Kerberos Service Ticket Operations (Success and Failure)
- Kerberos Authentication Service (Success and Failure)
- Directory Service Access (Success and Failure)
- Directory Service Changes (Success and Failure)
- Account Logon (Success and Failure)
- Logon/Logoff (Success and Failure)

---

## Methodology

Each test was isolated by filtering Elasticsearch queries to the specific account used in that test run, scoped to a 2-3 minute window immediately after the operation completed. This eliminates background domain noise from machine accounts, scheduled tasks, and service account activity that runs continuously on any live AD environment.

The key fields tracked per event:

- `event.code` — Windows Event ID
- `winlog.event_data.TargetUserName` — the account being acted upon
- `winlog.event_data.ServiceName` — the Kerberos service principal
- `winlog.event_data.TicketOptions` — Kerberos ticket option flags
- `winlog.event_data.IpAddress` — source IP of the request

An important environmental note: Event ID 5136 (Directory Service Object Modified) did not fire during RBCD testing despite the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute being successfully written. This is consistent with default AD environments where per-object SACLs are not configured on computer objects — 5136 requires both the audit policy and a SACL on the specific object. In its place, Event ID 4742 (Computer Account Changed) fired reliably, providing equally actionable detection coverage for defenders.

---

## Test Results

### Test 1 — Targeted LDAP Enumeration, Password Authentication

**Command:**

```bash
python3 delegator.py -d delegator.lab -u htb-user \
  --dc-ip 192.168.10.10 -p Password123! enum --constrained
```

![DeleGator terminal output for Test 1](/assets/img/2026-06-02-DeleGator/1.png)

**Events generated (filtered to htb-user):**

|Event ID|Description|Count|
|---|---|---|
|4776|NTLM Credential Validation|18|
|4624|Account Logon|18|
|4634|Account Logoff|18|

Kibana filter:
```
winlog.event_data.TargetUserName: "htb-user" AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing 54 events for Test 1](/assets/img/2026-06-02-DeleGator/2.png)

**Total: 54 events**

**Analysis:** Password authentication against LDAP triggers NTLM credential validation (4776) for each connection attempt. The ldap3 library establishes multiple short-lived connections during enumeration, producing 18 logon/validation/logoff cycles. No Kerberos events (4768/4769) were generated since NTLM was used for the LDAP bind. No directory service access events (4662) fired — consistent with default environments where per-object SACLs are not configured.

**Detection rules fired:** None

---

### Test 2 — Targeted LDAP Enumeration, Kerberos ccache Authentication

**Command:**

```bash
getTGT.py delegator.lab/htb-user:Password123! -dc-ip 192.168.10.10
export KRB5CCNAME=htb-user.ccache
python3 delegator.py -d delegator.lab -u htb-user \
  --dc-ip 192.168.10.10 --ccache htb-user.ccache enum --constrained
```

![DeleGator terminal output for Test 2](/assets/img/2026-06-02-DeleGator/3.png)

**Events generated (filtered to htb-user):**

|Event ID|Description|Count|
|---|---|---|
|4768|Kerberos TGT Request (AS-REQ)|1|
|4769|Kerberos Service Ticket Request (TGS-REQ)|1|
|4771|Kerberos Pre-Auth Failed|1|

Kibana filter:
```
winlog.event_data.TargetUserName: "htb-user" AND host.name: "DC01.delegator.lab" AND event.code: ("4768" OR "4769")
```

![Kibana Discover showing 3 events for Test 2 — contrast with Test 1's 54](/assets/img/2026-06-02-DeleGator/4.png)

**Total: 3 events**

**Analysis:** Using a pre-obtained ccache eliminates all NTLM events entirely. The single 4768 was generated by `getTGT.py` to obtain the ccache — if the operator already has a valid ccache from a previous operation this event is also eliminated, reducing the total to a single 4769 for the LDAP service ticket request. The 4771 is a transient pre-authentication failure that occurs during the initial TGT acquisition and is not attributable to the enumeration itself.

**OPSEC improvement over Test 1: 54 events → 3 events — an 18x reduction in event volume**

**Detection rules fired:** None

---

### Test 3 — Full Enumeration (All Delegation Types), Kerberos ccache Authentication

**Command:**

```bash
python3 delegator.py -d delegator.lab -u htb-user \
  --dc-ip 192.168.10.10 --ccache htb-user.ccache enum
```

![DeleGator terminal output showing all three delegation types enumerated](/assets/img/2026-06-02-DeleGator/5.png)

**Events generated (filtered to htb-user):**

|Event ID|Description|Count|
|---|---|---|
|4768|Kerberos TGT Request|1|
|4769|Kerberos Service Ticket Request|1|
|4624|Account Logon|2|

Kibana filter:
```
winlog.event_data.TargetUserName: "htb-user" AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing 4 events for Test 3](/assets/img/2026-06-02-DeleGator/6.png)

**Total: 4 events**

**Analysis:** Running full enumeration across all three delegation types (unconstrained, constrained, RBCD) with ccache auth generates the same Kerberos event profile as targeted enumeration — a single 4768 and 4769. The additional LDAP queries for unconstrained and RBCD enumeration do not produce additional Kerberos events since the existing service ticket is reused across connections. The 2 extra 4624 events represent the additional LDAP session establishments for the broader query scope. DeleGator's targeted filter approach — querying specific attributes rather than performing broad directory dumps — keeps event volume flat regardless of enumeration scope.

**Detection rules fired:** None

---

### Test 4 — Constrained Delegation Exploitation (S4U2Self + S4U2Proxy)

**Command:**

```bash
python3 delegator.py -d delegator.lab -u svc-mssql \
  --dc-ip 192.168.10.10 -p Password123! exploit \
  --type constrained \
  --service-account svc-mssql \
  --target-spn MSSQLSvc/DC01.delegator.lab:1433
```

![DeleGator terminal output showing successful S4U2Self + S4U2Proxy chain and ccache output](/assets/img/2026-06-02-DeleGator/7.png)

**Events generated (filtered to svc-mssql):**

|Event ID|Description|Count|Key Fields|
|---|---|---|---|
|4768|Kerberos TGT Request|1|TargetUserName: svc-mssql, TicketOptions: 0x50800000|
|4769|Kerberos Service Ticket Request (S4U2Self)|1|ServiceName: svc-mssql, TicketOptions: 0x40810000|
|4776|NTLM Credential Validation|1|TargetUserName: svc-mssql|
|4624|Account Logon|1|TargetUserName: svc-mssql|

Kibana filter:
```
winlog.event_data.TargetUserName: "svc-mssql" AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing svc-mssql events](/assets/img/2026-06-02-DeleGator/8.png)

S4U2Self fingerprint filter:
```
winlog.event_data.TicketOptions: "0x40810000" AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing the 4769 S4U2Self event with TicketOptions 0x40810000 highlighted](/assets/img/2026-06-02-DeleGator/9.png)

**Total: 4 events**

**Analysis:** The S4U2Self request is clearly fingerprinted by `TicketOptions: 0x40810000` in the 4769 event. This specific flag combination is part of the S4U2Self protocol specification and cannot be modified — it will always appear in this form when S4U2Self is used regardless of the tool. This is the primary detection indicator for constrained delegation abuse and the field most detection rules target. The LDAP enumeration phase (querying svc-mssql's delegation attributes) generated the NTLM 4776/4624 events due to password auth being used. Using ccache auth for this operation would eliminate those two events, leaving only the unavoidable 4768 and 4769.

**Detection rules fired:** None (custom S4U2Self rule did not fire — TicketOptions field mapping requires additional Kibana configuration)

**Note for defenders:** A detection rule querying `event.code: "4769" AND winlog.event_data.TicketOptions: "0x40810000"` will reliably identify S4U2Self requests. Baselining legitimate S4U activity in the environment before alerting is recommended to reduce false positives.

---

### Test 5 — RBCD Exploitation (Full Chain)

**Command:**

```bash
python3 delegator.py -d delegator.lab -u svc-web \
  --dc-ip 192.168.10.10 -p Password123! exploit \
  --type rbcd --target SRV03 \
  --delegate-account svc-web --delegate-pass Password123! \
  --impersonate administrator --cleanup
```

![DeleGator terminal output showing RBCD write, S4U chain, and ccache output with noise profile](/assets/img/2026-06-02-DeleGator/10.png)

**Events generated (filtered to svc-web and SRV03$):**

|Event ID|Description|Count|Key Fields|
|---|---|---|---|
|4742|Computer Account Changed|2|TargetUserName: SRV03$|
|4768|Kerberos TGT Request|4|Multiple accounts in S4U chain|
|4769|Kerberos Service Ticket Request|4|S4U2Self + S4U2Proxy requests|
|4776|NTLM Credential Validation|4|TargetUserName: svc-web|
|4624|Account Logon|4|TargetUserName: svc-web|
|4634|Account Logoff|4|TargetUserName: svc-web|
|4625|Failed Logon|2|Initial auth attempts|

Kibana filter:
```
winlog.event_data.TargetUserName: ("svc-web" OR "SRV03$") AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing all RBCD events](/assets/img/2026-06-02-DeleGator/11.png)

Computer account modification filter:
```
event.code: "4742" AND winlog.event_data.TargetUserName: "SRV03$" AND host.name: "DC01.delegator.lab"
```

![Kibana Discover showing the two 4742 events for the RBCD write and cleanup](/assets/img/2026-06-02-DeleGator/12.png)

**Total: 24 events**

**Analysis:** RBCD exploitation generates the highest event volume of any DeleGator operation. The two 4742 events represent the RBCD attribute write and the subsequent cleanup (`--cleanup` flag) — each modification to the computer account generates one 4742 event. Note that Event ID 5136 (Directory Service Object Modified) did not fire despite the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute being successfully written, because per-object SACLs were not configured on the SRV03 computer object. In environments where defenders have explicitly enabled SACL auditing on computer objects, 5136 will also fire with `AttributeLDAPDisplayName: msDS-AllowedToActOnBehalfOfOtherIdentity` — a highly specific and reliable RBCD detection indicator.

The four 4768/4769 pairs reflect the complete S4U chain: TGT acquisition for svc-web, TGT acquisition for the delegation account, S4U2Self, and S4U2Proxy. The `--cleanup` flag adds one additional 4742 but removes the persistent RBCD attribute from the environment, which is the correct operational choice.

**Detection rules fired:** None (4742 on computer accounts is not covered by default Elastic detection rules — a custom rule is recommended)

**Recommended custom detection rule:**

```
event.code: "4742" AND winlog.event_data.TargetUserName: *$
AND NOT winlog.event_data.SubjectUserName: "DC01$"
```

This fires on any computer account modification not initiated by the DC itself — a reliable RBCD write indicator in environments without SACL auditing.

---

## OPSEC Summary Table

|Operation|Auth Method|Event IDs|Total Events|Noise Rating|
|---|---|---|---|---|
|Targeted enum (single type)|Password/NTLM|4776, 4624, 4634|54|MEDIUM|
|Targeted enum (single type)|ccache/Kerberos|4768, 4769|2-3|LOW|
|Full enum (all types)|ccache/Kerberos|4768, 4769, 4624|4|LOW|
|Constrained exploitation|Password/NTLM|4768, 4769 (0x40810000), 4776, 4624|4|MEDIUM|
|RBCD exploitation|Password/NTLM|4742, 4768, 4769, 4776, 4624, 4634|24|HIGH|
|RBCD exploitation|ccache/Kerberos|4742, 4768, 4769|~10|MEDIUM*|

RBCD with ccache auth was not explicitly tested in this run. The estimate reflects elimination of the NTLM 4776/4624/4634 events, leaving only the unavoidable S4U Kerberos events and the 4742 computer account modification. This will be validated in a future test iteration.

---

## Key Findings

**ccache authentication is the single most impactful OPSEC improvement available.** Switching from password to ccache auth for the same enumeration operation reduces event volume from 54 events to 3 — an 18x reduction. Every NTLM credential validation (4776) and the associated logon/logoff cycle is eliminated entirely. In environments with mature detection, NTLM authentication against a domain controller from a non-standard workstation is itself a detection signal independent of what the authentication is being used for.

**Full enumeration and targeted enumeration produce the same Kerberos event profile.** DeleGator's targeted LDAP filter approach means running all three delegation type queries generates no more Kerberos events than running a single query type. The additional LDAP queries reuse the existing service ticket rather than requesting new ones, keeping event volume flat regardless of enumeration breadth.

**S4U2Self is permanently fingerprinted by TicketOptions 0x40810000.** This is a protocol-level characteristic that cannot be modified by any tool implementing S4U2Self — it will always produce a 4769 event with this specific ticket options value. Detection is reliable and unavoidable. The mitigation is operational: use existing service account credentials rather than triggering unnecessary additional TGT requests, and where possible use ccache auth to avoid the NTLM events that accompany the LDAP enumeration phase.

**RBCD writes are detectable via 4742 even without SACL auditing.** The conventional wisdom is that RBCD detection requires 5136 events, which in turn require per-object SACL configuration on computer objects — a non-default setting. In practice, 4742 (Computer Account Changed) fires reliably on any computer object modification including RBCD attribute writes, without requiring any additional configuration beyond standard account management auditing. Blue teams do not need to configure SACLs to detect RBCD writes.

**The --cleanup flag is always worth using.** It generates one additional 4742 event but removes the RBCD attribute from the environment, eliminating the persistent indicator and limiting dwell time exposure. The marginal increase in noise from a single extra event is outweighed by the reduction in forensic footprint.

---

## Detection Recommendations for Defenders

Based on the testing results, the following detection rules are recommended for environments seeking coverage against DeleGator and similar delegation abuse tools:

**RBCD write detection (no SACL required):**

```
event.code: "4742"
AND winlog.event_data.TargetUserName: *$
AND NOT winlog.event_data.SubjectUserName: (*$ OR "SYSTEM")
```

**S4U2Self detection:**

```
event.code: "4769"
AND winlog.event_data.TicketOptions: "0x40810000"
```

**NTLM authentication from non-domain workstations (enumeration indicator):**

```
event.code: "4776"
AND NOT winlog.event_data.Workstation: (known_workstations)
```

**RBCD write detection (with SACL auditing configured):**

```
event.code: "5136"
AND winlog.event_data.AttributeLDAPDisplayName: "msDS-AllowedToActOnBehalfOfOtherIdentity"
```

---

## Conclusion

DeleGator started from a specific frustration: the delegation attack surface is well-documented in research but the tooling to abuse it from Linux is fragmented, OPSEC-unaware, and requires significant manual work to go from a finding to a working ticket. The goal was to build something that closes that gap entirely — one tool, one command, enumeration through to ccache output, with honest documentation of what it generates along the way.

The OPSEC testing in this writeup reflects that philosophy. The 18x event reduction from ccache authentication, the 4742 RBCD detection finding, and the S4U2Self TicketOptions fingerprint data are all concrete, reproducible results from a real environment rather than theoretical claims. Anyone running DeleGator against a monitored target can use this data to make informed decisions about which auth method to use and which operations require the most care.

The tool will continue to be tested against real HTB delegation machines and updated as new findings emerge. The lab environment and test methodology described here will be used for all future OPSEC validation.

Source code and further documentation: [github.com/cbev0x/DeleGator](https://github.com/cbev0x/DeleGator)
