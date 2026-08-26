---
title: "I NSPI With My Little Eye: Enumerating Active Directory Through Exchange's Address Book Interface"
date: 2026-08-26
categories: [Personal, Research]
tags: [Windows, Active Directory, NSPI, Red Teaming, OPSEC, Research]
published: true
---

Every mature blue team eventually builds detection for SharpHound. The LDAP-sweep signature is well-understood: a single source account issuing hundreds of queries against the domain controller, pulling users, groups, ACLs, and trusts in rapid succession. MDI has dedicated analytics for it. LDAP expensive-query thresholds fire on the bulk access pattern. The category of "LDAP-based directory enumeration" is effectively a solved detection problem in shops that have invested in it.

This post documents a different path to the same data, one that runs over a different interface, blends into traffic already present on the wire, and surfaces objects that every existing LDAP-based collector misses entirely, including accounts that administrators have deliberately hidden from the directory. I also release [NSPIder](https://github.com/cbev0x/NSPIder), a BloodHound-CE collector built on top of these findings.

---

## The Interface Nobody Talks About

The Name Service Provider Interface (MS-NSPI) is the RPC protocol Outlook uses to talk to the Exchange address book. When you type a name in the To: field and Outlook resolves it, that is NSPI. When Outlook downloads the Global Address List, that is NSPI. The interface has existed since Exchange 5.5 and is present in every on-premises Exchange deployment in production today.

NSPI is served by the Global Catalog, not by the Exchange server itself. This distinction matters and I will return to it. The interface UUID is `F5CC5A18-4264-101A-8C59-08002B2F8426`, registered over `ncacn_ip_tcp` on the GC via the endpoint mapper. Any authenticated domain account can bind to it. No special permissions are required.

Impacket ships a full implementation in `dcerpc.v5.nspi`, contributed by mohemiv of PT SWARM following their 2020 research into address book operations. An example tool called `exchanger.py` demonstrates some of its capabilities. What nobody had built before NSPIder is a BloodHound-compatible collector on top of it, or a systematic characterization of what NSPI actually exposes as an offensive enumeration surface.

---

## Lab Setup

All testing was performed against a Windows Server 2025 domain (reflect.lab) running Exchange Server 2019 CU15, with a WS2025 GC (DC01 at 10.10.20.10) and a WS2025 Exchange server (EXCH01 at 10.10.20.45). The collector ran from Kali using Impacket 0.14.0.dev0. The test credential was jdoe, a member of Domain Users with no additional group memberships.

For the footprint measurements, I enabled Directory Service Access auditing on DC01 before each test run and used `Get-WinEvent` with tight timestamp windows to count events per collection mode.

---

## The Two-Plane Architecture

The first thing I discovered, before any bypass research, was that NSPI's operation set splits across two physical servers. Running `impacket-rpcdump` against both boxes revealed the split cleanly.

**DC01 (GC):**
```
Protocol: [MS-NSPI]: Name Service Provider Interface (NSPI) Protocol
UUID    : F5CC5A18-4264-101A-8C59-08002B2F8426 v56.0
Binding : ncacn_ip_tcp:10.10.20.10[49677]
```

**EXCH01:**
```
Protocol: [MS-OXABREF]: Address Book Name Service Provider Interface (NSPI) Referral Protocol
UUID    : 1544F5E0-613C-11D1-93DF-00C04FD7BD09 v1.0
Binding : ncacn_ip_tcp:10.10.20.45[...]
```

EXCH01 hosts the referral interface (MS-OXABREF). When an Outlook client connects, it first asks EXCH01 "which GC should I use for address book operations?" and gets referred to DC01. All actual data operations then happen directly against DC01's NSPI endpoint.

This architecture defines what I call the **data plane** and the **resolution plane**:

The **data plane** lives on the GC. It handles raw directory reads: `NspiQueryRows`, `NspiQueryColumns`, `NspiGetSpecialTable`, `NspiUpdateStat`, and `NspiGetProps`. Any authenticated account can call these. They return whatever the DIT holds at the requested positions.

The **resolution plane** lives in Exchange's address-book service on EXCH01. It handles `NspiResolveNamesW` (Ambiguous Name Resolution, what Outlook uses when you type partial names), `NspiGetMatches` (server-side restriction queries), and the membership/hierarchy proptags like `PidTagAddressBookMember`. These operations require the Exchange AB service in the request path. Connecting directly to DC01's NSPI with these calls returns `MAPI_E_CALL_FAILED`.

NSPIder operates entirely on the data plane. The resolution plane is a separate attack surface, outside the scope of this post.

On a bare AD forest with no Exchange, the NSPI endpoint does not register on the GC at all. The `ept_s_not_registered` error from the endpoint mapper is the signal that Exchange has not run `/PrepareSchema` against this domain.

---

## Browse Walk: What the Address Book Shows

NSPI exposes two collection primitives. The first is a container-filtered walk using `NspiQueryRows` against a container ID. The container is the exchange-managed address list structure: the Default Global Address List (GAL), All Users, All Groups, and so on.

A browse walk against the reflect.lab GAL returned 578 proptags and four visible objects:

```
Administrator    [User/Mailbox]   S-1-5-21-951449822-...-500
Alice Reed       [User/Mailbox]   S-1-5-21-951449822-...-3663
AllStaff-DL      [DistList]       S-1-5-21-951449822-...-3666
Bob Chen         [User/Mailbox]   S-1-5-21-951449822-...-3664
```

`objectSid` is reachable at proptag `0x80270102` and Impacket decodes it to a canonical SID string. `objectGUID` is at `0x8c6d0102`. Both are available per-object on every row returned, which means BloodHound-CE node keys are SID-based and merge cleanly with any other collector's output without a GUID bridge.

The container walk looks like Outlook. From a traffic perspective, it is Outlook.

---

## The MId-Range Scan: What the Address Book Hides

The second NSPI primitive is the one that produces the interesting results. `NspiQueryRows` accepts an optional parameter `lpETable`, an explicit list of Message IDs (MIds). When present, the server skips the container's sorted table and returns the objects at those specific DIT positions directly.

MIds are session-scoped sequential integers assigned by the NSPI server. Cycling through a range of them from 1 to 20,000 in batches of 50 issues 400 `NspiQueryRows` calls and traverses essentially the entire DIT. The results are not filtered by any address book container. Whatever is at that DIT position comes back.

In the reflect.lab environment, that same lab that showed four visible objects in the browse walk returned **7,394 objects** from the MId-range scan, resolving to **65 users and 110 groups** after SID-based node filtering.

The 171 hidden objects flagged in the output include: accounts with `msExchHideFromAddressLists = True`, accounts outside the Default GAL's mail-enabled population entirely, all AD built-in groups (Domain Admins, Schema Admins, Administrators, etc.) with their SIDs, Exchange service mailboxes, and non-Exchange domain accounts that happen to exist in the DIT at those positions.

---

## Bypass 1: GAL Hiding

`msExchHideFromAddressLists` is the Exchange attribute that controls whether a mail-enabled object appears in address lists. Administrators use it to hide service accounts, resource mailboxes, and sensitive distribution lists from the Global Address List. It is a commonly deployed soft control.

I created two objects with this flag set to `True` in the lab: a mailbox named Svc Backup and a distribution list named Secret-Ops-DL. A browse walk returned neither. The MId-range scan returned both, with full SIDs and email addresses:

```
mid=10418  Svc Backup     [User/Mailbox]  S-1-5-21-...-3665  svcbackup@reflect.lab  *** HIDDEN
mid=10420  Secret-Ops-DL  [DistList]      S-1-5-21-...-3667  Secret-Ops-DL@reflect.lab  *** HIDDEN
```

This is a presentation-layer bypass, not a security boundary violation. Microsoft's own documentation states that hiding from address lists "is not a mail delivery restriction or security boundary." The attribute controls address book visibility; it has never been claimed to prevent directory access. What the MId-range scan demonstrates is the concrete mechanism by which a caller bypasses it: by addressing objects by their DIT position rather than through a container, the server returns them without evaluating the hide flag.

No MSRC report. This is tradecraft, and it is documented here as such.

---

## Bypass 2: Address Book Policy Segmentation

Address Book Policy (ABP) is an Exchange feature that assigns each mailbox a restricted view of the directory. A user assigned an ABP with a limited GAL can only see the objects in that GAL through their Outlook client. Multi-tenant Exchange environments and organizations that use Exchange to model departmental segmentation rely on ABP to scope what users can discover.

I assigned Bob Chen a `RestrictedABP` whose GAL contained only Alice Reed. Through Outlook, Bob's address book search returns one result. Through NSPIder connecting as Bob against DC01's NSPI endpoint directly, the browse walk returned the same four visible objects that jdoe (no ABP) sees. The MId-range scan, also run as Bob, returned all 137 mail-typed objects in the cycle range.

ABP is enforced by the Exchange address-book service on EXCH01. It is not enforced by the GC's NSPI data plane. When a client connects directly to DC01 rather than routing through EXCH01's referral and AB service, the GC has no knowledge of the ABP assignment and applies no filtering. Any domain account bypasses ABP segmentation through this path, regardless of what policy is assigned to their mailbox.

---

## Bypass 3: The Mail-Enabled Filter

The most significant finding is not the hiding bypass or the ABP bypass. It is the scope of what the MId-range scan returns.

Address book collectors, by definition, work against the address book. The address book is a mail-enabled subset of the directory. Non-mail-enabled objects, accounts that have never had an Exchange mailbox, AD security groups that exist purely for access control, and service accounts that predate Exchange in the environment are simply not present in any NSPI container browse.

The MId-range scan does not use containers. It reads DIT positions. Any object in the DIT with a display name at a scanned position comes back. In reflect.lab, that included:

- All domain users, whether mail-enabled or not, including research accounts (`ap_control`, `svc-ces`, `rodc_cached_user`), Tier-0 accounts (`t0user`, `T0-PAWs`), and test accounts from previous lab exercises
- All AD built-in and domain groups with their SIDs: Domain Admins, Schema Admins, Administrators, Enterprise Admins, krbtgt
- Every Exchange service account: 11 HealthMailbox accounts, SystemMailbox, federation mailboxes, the migration service account, the approval assistant mailbox

The practical implication is that NSPIder is not an Exchange address-book collector that happens to bypass some filters. It is a full domain enumeration tool that uses NSPI as its transport. The BloodHound output from a single NSPIder run against a domain with 500 Exchange recipients might contain 2,000 user and group nodes, because the MId-range scan sees the whole directory.

---

## Footprint Comparison

The footprint measurements below come from `Get-WinEvent` captures with tight timestamp windows on DC01 during each collection pass. Auditing was enabled for Directory Service Access before each run.

| Mode | Tool | 4662 | 4624 | 4769 | 5145 | Window |
|---|---|---|---|---|---|---|
| NSPI browse walk | nspi_probe.py | 0 | 4 | 0 | 0 | ~16s |
| NSPI MId-cycle (20k MIds, 400 calls) | nspi_t2_cycle.py | 0 | 1 | 0 | 0 | ~15s |
| LDAP baseline | nxc --users --groups | 0 | 4 | 1 | 0 | ~27s |
| SAMR baseline | impacket-lookupsid | 0 | 1 | 0 | 0 | ~11s |

Event 4662 (Directory Service object access) fires only when the accessed object carries a matching SACL. Default DC configuration carries no read-access SACLs on most objects, so 4662 equals zero for all four techniques under default configuration. This is not NSPI-specific stealth; it applies equally to LDAP and SAMR. A defender with custom SACLs on sensitive objects would see 4662 for all four methods identically.

The meaningful difference is in event 4769, which logs Kerberos service ticket requests. LDAP generates one 4769 because NetExec requests an `ldap/DC01` service ticket explicitly. The NSPI sessions generate zero 4769 events, likely because the service ticket for the NSPI endpoint is obtained earlier (during the EPM resolution phase) and cached rather than logged as a separate event.

The most important number is the MId-cycle row: 400 RPC calls traversing 20,000 DIT positions, resolving 65 users and 110 groups, in approximately 15 seconds, generating one logon event. The traffic pattern during that window is indistinguishable from a single Outlook client refreshing its local address book copy.

A tuned SOC running MDI can detect the NSPI-specific RPC browse request rate on the DC's performance counters. The tell is request rate, not protocol or event logs. The `--jitter` flag in NSPIder adds a random inter-batch sleep to flatten the request rate at the cost of collection speed.

---

## DNToMId: Precision Access Without Enumeration

`NspiDNToMId` converts an Exchange legacy distinguished name (`legacyExchangeDN`) to a session-scoped MId. Once you have the MId, a single `NspiQueryRows` call with `lpETable=[mid]` returns the full property set for that specific object.

The `legacyExchangeDN` attribute is readable from LDAP at any privilege level. Its format is:

```
/o={OrgName}/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn={mailboxGUID}-{displayName}
```

The `mailboxGUID` prefix is Exchange's internal GUID for the mailbox object, not the AD `objectGUID`. It is only obtainable from the `legacyExchangeDN` attribute itself.

The attack chain is:

1. LDAP query for `legacyExchangeDN` on the target account (one authenticated LDAP query)
2. `NspiDNToMId` with that DN (one NSPI call)
3. `NspiQueryRows` with `lpETable=[mid]` (one NSPI call)

The result is full property access, including SID and email address, for a specific account, including GAL-hidden accounts, with a total footprint of approximately two logon events. The lab result for the Svc Backup hidden mailbox:

```
RESOLVED *** HIDDEN: svcbackup -> MId=10418
  DN   : /o=reflectlab/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=a99eb37d44cd4f4aaa203023b5abc3f8-Svc Backup
  Props: Svc Backup [User/Mailbox] sid=S-1-5-21-...-3665 mail=svcbackup@reflect.lab
```

This is the precision-strike complement to the MId-range scan. When the target account is known (named in a phishing scope, identified via OSINT, or discovered through other recon), DNToMId retrieves it with minimal noise. When the target population is unknown, the bulk MId-range scan discovers it. NSPIder uses the bulk scan by default; DNToMId support is planned for a future release.

---

## Infrastructure Disclosure

A secondary finding from the MId-range scan is that Exchange's internal service accounts, visible in the DIT at their allocated positions, disclose deployment details that would otherwise require LDAP access or Exchange admin rights to obtain.

The reflect.lab environment had no LDAP query run against it during the NSPIder collection pass. The tool connected once to NSPI and ran the cycle. From the resulting output, you can determine:

- The Exchange server hostname (EXCH01, from the HealthMailbox account names: `HealthMailbox-EXCH01-001` through `-010`)
- The mailbox database GUID (`0145442605`, from `HealthMailbox-EXCH01-Mailbox-Database-0145442605`)
- The Exchange system mailbox GUID (`8cc370d3-822a-4ab8-a926-bb94bd0641a9`, from `SystemMailbox{8cc370d3-...}`)
- Whether federation and hybrid are configured (the presence of `Microsoft Exchange Federation Mailbox` and `Exchange Online-ApplicationAccount`)
- Whether eDiscovery/compliance search is active (the presence of `Discovery Search Mailbox`)
- Whether the mail transport approval service is running (`Microsoft Exchange Approval Assistant`)

Additionally, machine accounts from other research contexts were visible at their DIT positions: `NDES01$` (NDES/ADCS), `SAMBA$`, `SRV01$`, `SRV02`. These are not Exchange objects. They surfaced because the MId-range scan reads DIT positions without filtering by object class or Exchange configuration.

An operator who establishes NSPI access before any LDAP enumeration can determine significant infrastructure topology from the cycle output alone, with no LDAP session and no domain controller log entries beyond the initial logon.

---

## NSPIder

[NSPIder](https://github.com/cbev0x/NSPIder) is the tool that came out of this research. It is a single-file Python collector that produces BloodHound-CE v6 JSON ready for direct import.

**Installation:**

```bash
pip install impacket
git clone https://github.com/cbev0x/NSPIder
```

**Basic usage:**

```bash
# Password auth
python3 NSPIder.py reflect.lab/jdoe:'Password1'@10.10.20.10

# NT hash
python3 NSPIder.py reflect.lab/jdoe@10.10.20.10 -hashes :NTHASH

# Kerberos
python3 NSPIder.py reflect.lab/jdoe@dc01.reflect.lab -k
```

Output lands in `NSPIder_<domain>_<timestamp>/` as two files: `users.json` and `groups.json`. Both are importable directly into BloodHound-CE. Objects not visible in the address book are tagged `nspi_hidden: true` in the Properties block so analysts can immediately identify what standard LDAP-based collectors would have missed.

**OPSEC tuning:**

```bash
# Add inter-batch jitter and narrow the MId range for a quieter pass
python3 NSPIder.py reflect.lab/jdoe:'Password1'@10.10.20.10 \
  --jitter 200 --mid-start 4000 --mid-end 15000
```

**LDAP enrichment for group membership edges:**

By default NSPIder generates no LDAP traffic at all. Adding `--enrich` opens one targeted LDAP session to pull group membership for the groups discovered during the NSPI collection pass. This populates `MemberOf` edges in the output at the cost of one additional logon event and a LDAP signing negotiation.

```bash
# Enrich only groups matching a substring (targeted, minimal LDAP)
python3 NSPIder.py reflect.lab/jdoe:'Password1'@10.10.20.10 \
  --enrich --enrich-filter "domain admins"
```

**BOFHound compatibility:**

```bash
python3 NSPIder.py reflect.lab/jdoe:'Password1'@10.10.20.10 --bofhound
```

Emits a single combined JSON file compatible with BOFHound v2+ ingestion, useful when operating offline or without a running BloodHound-CE instance.

---

## Limitations and Scope

NSPIder requires Exchange to have run `/PrepareSchema` against the target domain. A bare AD forest without Exchange will return `ept_s_not_registered` from the endpoint mapper. This is not a limitation I can work around; the NSPI endpoint simply does not exist until Exchange registers it.

The following operations are explicitly out of scope for the direct-GC path this tool uses:

- `NspiResolveNamesW` (Ambiguous Name Resolution) -- requires the Exchange address-book service on EXCH01
- `NspiGetMatches` (server-side restriction queries) -- same requirement
- Group membership and org hierarchy proptags (`PidTagAddressBookMember`, `PidTagAddressBookManager`, `PidTagAddressBookReports`) -- absent from the GC's exposed proptag set

These live in what I described above as the resolution plane. The EXCH01 RPC-over-HTTP path supports them, but Exchange 2019 CU15 enables Extended Protection by default, which blocks Impacket's NTLM implementation on that path. Kerberos avoids the channel-binding requirement. A follow-on tool targeting the EXCH01 path with Kerberos auth would add membership edges and org-hierarchy traversal to what is already collectible through NSPIder.

The MId range of 1-20,000 covers the lab environment and most mid-size organizations. Large domains may need `--mid-end 50000` or higher. A future version will auto-detect the populated range from the browse walk results to avoid scanning empty regions.

---

## Closing Thoughts

The NSPI bypass findings documented here are tradecraft observations about a soft control that was never designed to be a security boundary. Microsoft does not claim that `msExchHideFromAddressLists` prevents directory access, and the ABP model has always been documented as a user experience control rather than an access control model. Nothing here warrants an MSRC report.

What it does warrant is awareness. Organizations that deploy ABP for compliance segmentation or that rely on GAL hiding to conceal service accounts from ordinary users should understand that any domain account with network access to the GC can enumerate the full directory population via NSPI, regardless of what the address book displays. The correct control for concealing sensitive accounts from directory enumeration is ACL-based, not presentation-layer.

The NSPI surface has been sitting in Impacket since mohemiv's contribution in 2020. NSPIder adds the BloodHound-graph layer and characterizes the bypass surface. The full characterization data, including raw proptag outputs, telemetry captures, and the complete lab protocol, is available in the research archive linked from the repository.

---

*Tested against Exchange Server 2019 CU15 on Windows Server 2025. Results may vary across Exchange versions.*

*Tool: [github.com/cbev0x/NSPIder](https://github.com/cbev0x/NSPIder)*
