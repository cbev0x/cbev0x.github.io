---
title: "Kerberos Secret Caching, Hub Forwarding, and Account Revocation Behavior"
date: 2026-08-15
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, RODC, Research]
published: true
---

## Executive Summary

Read-only domain controllers are designed to provide branch authentication while limiting the credentials exposed at a less trusted site. Their behavior is governed by several mechanisms that interact but do not have identical lifecycles: Password Replication Policy, the RODC's local password cache, its branch-specific `krbtgt_<number>` account, writable-domain-controller forwarding, Kerberos ticket lifetimes, and Windows account-revocation checks.

I built an isolated Windows Server 2025 lab to examine how those mechanisms behave when their state stops agreeing. The testing covered users whose current secrets were cached or uncached, explicit PRP allow and deny decisions, cached service-account secrets, user and service password rotations, retained branch TGTs, disabled accounts, native Windows KDC routing, and direct raw Kerberos requests to the RODC. Each important state transition was validated through Active Directory metadata, `klist`, Security events, and packet captures.

The first major result was that changing an account from PRP Allow to `DenyExplicit` did not remove a secret that had already been revealed to the RODC. The account continued authenticating locally and receiving branch-issued Kerberos tickets until its password changed. PRP therefore controlled whether a current or future secret could be replicated, but it did not operate as a retroactive purge mechanism for material that was already cached.

Password rotation provided the meaningful key boundary. When I rotated a denied user's password, the directory `msDS-KeyVersionNumber` advanced and the account disappeared from the RODC's current `RevealedAccounts` state. Fresh authentication was then forwarded through the RODC to its writable replication partner. A cached service account behaved similarly. Before rotation, the RODC issued the service ticket locally even after the service became explicitly denied by PRP. After rotation, the RODC could no longer issue a ticket for that service from its stale local key and the Windows client recovered through the writable-DC path.

The testing also separated user-secret freshness from ticket validity. A branch TGT issued before a password rotation remained usable afterward for TGS requests because the user password is not revalidated for every service-ticket request. However, the stale cached password could not be used to establish a new Kerberos authentication after the directory password changed. The retained ticket and the stale password were therefore two different security objects with different invalidation behavior.

The most interesting lifecycle behavior involved disabled accounts. A disabled user with a recently issued branch TGT could receive a replacement branch TGT and new RODC-local service tickets for approximately 20 minutes after the original authentication. If the requested service required writable-DC participation, the writable KDC immediately applied the disabled state and denied the request. Once the original authentication age exceeded approximately 20 minutes, the RODC itself returned `KDC_ERR_CLIENT_REVOKED` for a direct TGS request.

I then tested whether requesting replacement branch TGTs could restart that 20-minute interval. The native Windows client was not sufficient for the decisive test because it attempted to locate a writable KDC once validation became due. I therefore exported a branch TGT in the lab and used a raw Kerberos client to direct both stages to RODC01. A replacement branch TGT was successfully issued six minutes after the baseline authentication. Sixteen minutes after that replacement, but 22 minutes after the original authentication, RODC01 rejected a new service-ticket request with Kerberos error 18, `KDC_ERR_CLIENT_REVOKED`. The packet capture proved that both the replacement and final request were exchanged directly between WS01 and RODC01, with no writable KDC involved.

The replacement-TGT result disproved the strongest bypass hypothesis. The RODC's revocation interval was not reset by the replacement ticket's visible `StartTime`. The implementation retained or derived the original authentication age, most likely through Kerberos `authtime` or equivalent ticket authorization state. Repeated branch-TGT replacement could not extend disabled-account access indefinitely.

I do not currently consider these results a new security vulnerability. The approximately 20-minute disabled-account behavior matches Microsoft's documented KILE account-revocation design, and the attempted sliding extension was rejected. The research does, however, provide a detailed implementation map of RODC secret caching, key rotation, client fallback, and revocation behavior that is useful for both offensive research and incident-response planning.

---

## Background

### Read-Only Domain Controllers

An RODC contains a read-only copy of Active Directory and does not accept normal originating directory updates. It can act as a KDC at a branch site, but it does not necessarily possess every account's current password-derived Kerberos keys. Instead, it uses Password Replication Policy to determine which secrets may be replicated to it.

Each RODC also has a separate branch `krbtgt` account. In this lab, RODC01 used branch identifier `570`, which appeared in Windows ticket output as:

```text
TGT issued by branch: 570
```

Microsoft documents that each RODC uses a distinct Kerberos key version namespace so a domain controller can identify which RODC issued a ticket. The high 16 bits identify the RODC and the low 16 bits contain the key version. This lets a writable KDC distinguish tickets associated with different branches while limiting the consequences of a single RODC compromise.

### Password Replication Policy

Password Replication Policy determines whether an account's password-derived secrets may be replicated to an RODC. The important states in this research were:

- `Allow`: the RODC may cache the account's current secret.
- `DenyExplicit`: the account is directly denied for that RODC.
- `RevealedAccounts`: the RODC currently has a revealed version of the account secret.

I treated resultant PRP and revealed state as separate measurements. An account could be `DenyExplicit` while still appearing in `RevealedAccounts` because the secret had been cached before the PRP change. That distinction turned out to be central to the results.

### Branch and Hub Kerberos Processing

When the RODC has the necessary user and service keys, it can perform authentication and ticket issuance locally. When it does not have the required secret, Windows Kerberos supports forwarding or retry behavior involving a writable KDC. The exact behavior differs between AS and TGS processing and depends on client branch-awareness.

The native Windows client adds branch-aware information to TGS requests. If the RODC reports that it lacks the service secret, the client can obtain or use writable-DC ticket material and retry through the hub path. During testing, Windows exposed both branch and hub TGT state in the same logon session:

```text
Cache Flags: 0x1   -> PRIMARY
TGT issued by branch: 570

Cache Flags: 0x100 -> HUB-PRIMARY
```

This dual-cache behavior explained several captures that would otherwise have looked like contradictory local and forwarded processing.

### Account Revocation Checking

Kerberos does not normally re-read the user object for every TGS request. Microsoft's KILE extension checks whether the account remains in good standing when the TGT becomes older than an implementation-specific threshold. Microsoft documents the Windows threshold as approximately 20 minutes. Disabled, expired, locked, and logon-hours violations are evaluated through this account-policy check and produce `KDC_ERR_CLIENT_REVOKED` when enforcement applies.

The main revocation question in this research was whether an RODC-issued replacement TGT established a new 20-minute window or retained the original authentication age.

---

## Lab Environment

All testing was performed in an isolated VMware Active Directory lab with no Internet egress.

The primary systems were:

- Domain: `REFLECT.LAB`
- `DC01.reflect.lab`: writable Windows Server 2025 domain controller, `10.10.20.10`
- `DC03.reflect.lab`: writable Windows Server 2025 domain controller and RODC replication partner, `10.10.20.14`
- `RODC01.reflect.lab`: Windows Server 2025 read-only domain controller, `10.10.20.16`
- `WS01.reflect.lab`: Windows 11 25H2 client, `10.10.20.20`
- `SRV02.reflect.lab`: member server and uncached service target, `10.10.20.12`

RODC01 was placed in `RODC-Site`. Its inbound domain replication path was:

```text
DC01 -> DC03 -> RODC01
```

`repadmin /showrepl`, `repadmin /showconn`, `repadmin /syncall`, and `dcdiag /test:Replications` confirmed healthy inbound replication. RODC01's directory service state included `DISABLE_OUTBOUND_REPL` and `IS_RODC`, as expected.

The main research accounts were:

| Account | Purpose |
|---|---|
| `rodc_cached_user` | Baseline user whose secret was cached on RODC01 |
| `rodc_uncached_user` | Allowed but initially uncached user |
| `rodc_denied_user` | User denied by PRP |
| `rodc_u05c_user` | Branch and hub ticket-routing tests |
| `rodc_u06b_svc` | Cached service account owning `HTTP/rodc-u06b.reflect.lab` |
| `rodc_u07_user` | PRP Allow-to-Deny and user-password-rotation tests |
| `rodc_u08_user` | Stale branch-TGT and stale cached-password tests |
| `rodc_u09_user` | Disabled-account revocation and replacement-TGT tests |

All primary Kerberos tickets were AES-256, shown as encryption type `0x12` and `AES-256-CTS-HMAC-SHA1-96` in Windows output.

---

## Methodology and Evidence Controls

The tests were built around controlled state transitions rather than relying on one successful or failed logon. Before each important request, I recorded the account state from DC01, forced replication through DC03 to RODC01, purged the target logon session's ticket and KDC binding caches, and explicitly bound both `REFLECT` and `REFLECT.LAB` to RODC01 where the native client permitted it.

I used separate logon-session LUIDs so an elevated administrator could inspect and control the research user's Kerberos cache without mixing it with the administrator session. Typical preparation was:

```powershell
klist -li $targetLuid purge
klist -li $targetLuid purge_bind
klist -li $targetLuid add_bind REFLECT RODC01.reflect.lab
klist -li $targetLuid add_bind REFLECT.LAB RODC01.reflect.lab
```

The directory state was validated using:

```powershell
Get-ADAccountResultantPasswordReplicationPolicy
Get-ADDomainControllerPasswordReplicationPolicyUsage -RevealedAccounts
Get-ADUser -Properties PasswordLastSet,msDS-KeyVersionNumber
```

Kerberos Security events 4768, 4769, and 4771 were enabled and correlated across RODC01, DC03, and DC01. Packet captures were recorded with full packet size using `pktmon`, converted to `pcapng`, and preserved per test identifier. Where native Windows routing obscured which KDC made the decision, I used firewall routing controls or a raw Kerberos client directed to `10.10.20.16`.

The following Kerberos errors were especially useful:

| Error | Meaning in these tests |
|---|---|
| 7 | `KDC_ERR_S_PRINCIPAL_UNKNOWN`, used with RODC no-secret behavior for an uncached target service |
| 18 | `KDC_ERR_CLIENT_REVOKED`, account disabled or otherwise not in good standing |
| 20 | `KDC_ERR_TGT_REVOKED` |
| 24 | `KDC_ERR_PREAUTH_FAILED`, supplied password did not match the available key |
| 25 | `KDC_ERR_PREAUTH_REQUIRED`, normal first AS exchange |
| 29 | `KDC_ERR_SVC_UNAVAILABLE`, writable processing unavailable in the tested path |

---

## Baseline: Cached, Uncached, and Denied Accounts

The opening test matrix established the three basic RODC user states.

### Cached Account

`rodc_cached_user` had a revealed secret on RODC01. After binding the target session to RODC01 and emptying the Kerberos cache, the user performed a local AS exchange with RODC01 and received a branch TGT. A subsequent request for `host/RODC01.reflect.lab` was also completed locally.

The ticket cache showed:

```text
TGT issued by branch: 570
Kdc Called: RODC01.reflect.lab
```

The packet capture contained only WS01-to-RODC01 Kerberos traffic for the successful AS and TGS exchanges.

### Allowed but Initially Uncached Account

`rodc_uncached_user` was permitted by PRP but did not initially appear in RODC01's revealed list. The first authentication reached RODC01, which forwarded processing to DC03. DC03 returned the AS reply through RODC01. The subsequent service-ticket request also involved the writable KDC.

After that successful authentication and permitted secret replication, a repeated test completed locally at RODC01. The transition from forwarded processing to local branch issuance demonstrated automatic caching for an allowed user.

### Denied Account

`rodc_denied_user` was denied by PRP. Authentication through RODC01 was forwarded to DC03 and succeeded only through the writable path. Repeating the test did not convert the account into a local branch-authentication case because its secret was not permitted to replicate.

When writable KDC access was blocked, the same denied authentication failed with Kerberos error 29, `KDC_ERR_SVC_UNAVAILABLE`. This provided a negative control showing that the RODC did not possess or silently obtain a usable local secret for the denied account.

The baseline matrix was therefore:

| User state | First authentication | Later authentication |
|---|---|---|
| Secret already cached | Local RODC | Local RODC |
| Allowed, initially uncached | Forwarded to writable KDC | Local after caching |
| Denied, uncached | Forwarded to writable KDC | Continues requiring writable KDC |
| Denied with writable KDC unavailable | Fails | Fails |

---

## Branch TGTs and Writable-DC Fallback

The next tests examined what happens when the user can authenticate at the branch but the requested service cannot be satisfied from RODC01's local secrets.

`rodc_u05c_user` was used to obtain a clean branch TGT. When the target SPN was local to a secret known by RODC01, the service ticket was issued directly by the branch KDC. When the target required writable processing, the native client and RODC coordinated a hub path.

The most useful observation was that one logon session could contain both:

- a branch `PRIMARY` TGT marked `TGT issued by branch: 570`, and
- a `HUB-PRIMARY` TGT associated with writable processing.

In capture `RODC-U06A-R1.pcapng`, WS01 first authenticated `rodc_u05c_user` locally to RODC01. It then requested `cifs/SRV02.reflect.lab`. RODC01 did not have SRV02's current service secret and returned Kerberos error 7. The client performed the required writable-DC exchange through RODC01 and DC03, then obtained the CIFS ticket. The final cache contained the branch primary TGT, a hub-primary TGT, and the CIFS service ticket.

This behavior is important when interpreting `Kdc Called: RODC01.reflect.lab`. The client-facing KDC can remain RODC01 even though the packet capture proves that DC03 performed authoritative hub processing behind it.

---

## PRP Denial Does Not Purge an Already Cached User Secret

The clearest user-secret lifecycle test used `rodc_u07_user`.

The initial state was:

```text
Resultant PRP: Allow
RevealedOnRODC: True
```

With that state, U07A produced a local AS exchange, a branch TGT, and a local `host/RODC01.reflect.lab` service ticket. I then removed the user from the allowed PRP list and added it directly to the denied list. Replication was forced through DC03 to RODC01, and RODC01 reported:

```text
Resultant PRP: DenyExplicit
RevealedOnRODC: True
```

The password metadata remained unchanged:

```text
PasswordLastSet unchanged: True
KVNO unchanged: True
```

U07B then repeated fresh authentication from an empty user ticket cache. RODC01 still completed the AS and TGS exchanges locally. The user received a branch TGT and the requested service ticket even though its resultant PRP was now `DenyExplicit`.

This was not evidence that PRP denial was ignored. It showed that PRP denial did not retroactively erase the already revealed key. The current secret remained locally usable until a key-changing event occurred.

---

## Password Rotation Ends Local Authentication for a Denied User

I next reset `rodc_u07_user`'s password while the account remained `DenyExplicit`. The directory KVNO advanced from 3 to 4, replication was forced to DC03 and RODC01, and the account disappeared from the current revealed state:

```text
ResultantPRP: DenyExplicit
RevealedOnRODC: False
```

The decisive rerun was U07C-R1. WS01 sent the AS request to RODC01. RODC01 forwarded it to DC03, DC03 returned the AS reply, and the subsequent request for `host/RODC01.reflect.lab` also traversed the hub path. DC03 recorded successful events from client address `10.10.20.16`, which was RODC01 rather than WS01.

The password rotation changed the result because the RODC no longer possessed the current user key. The user could still authenticate through a reachable writable KDC, but no longer through branch-local secret validation.

The resulting lifecycle was:

```text
Secret cached while PRP allows account
        |
        v
PRP changed to DenyExplicit
        |
        v
Existing current secret remains locally usable
        |
        v
Password rotated on writable DC
        |
        v
Directory KVNO advances and current reveal state clears
        |
        v
Fresh authentication requires writable KDC
```

---

## Cached Service Accounts Follow the Same Key Boundary

The service-side version used `rodc_u06b_svc`, which owned:

```text
HTTP/rodc-u06b.reflect.lab
```

The service account was initially cached on RODC01. U06B showed RODC01 issuing the HTTP service ticket locally. I then changed the service account to `DenyExplicit` without changing its password. U06C still succeeded locally because the already revealed service key remained current.

I then rotated the service account password while it remained denied. `PasswordLastSet` changed and `msDS-KeyVersionNumber` advanced. In U06D, RODC01 could no longer issue a ticket from the stale local service key. The client first received Kerberos error 7 from RODC01, then recovered through DC03 and received the service ticket from the writable path.

This mirrored the user result:

| Service state | Result |
|---|---|
| Cached and allowed | Local RODC service-ticket issuance |
| Cached, then changed to `DenyExplicit` without rotation | Still local |
| Denied, then password rotated | RODC cannot use stale key; writable fallback |

The service-account test also demonstrates why `RevealedAccounts` should be interpreted as a statement about the current revealed credential generation, not as a permanent historical record of every key the RODC has ever held.

---

## Retained Branch TGTs Survive User Password Rotation

`rodc_u08_user` was used to separate the validity of an already-issued branch TGT from the validity of a cached password.

The user was initially allowed and its current password was prepopulated to RODC01. I obtained a branch TGT, changed the user to `DenyExplicit`, and rotated the password. The directory KVNO advanced and the current revealed state became false.

Without purging the branch TGT obtained before rotation, U08A requested a new RODC-local service ticket. The request succeeded. RODC01 issued a replacement branch TGT and the requested service ticket locally.

This is expected Kerberos ticket behavior. A TGS request is authenticated with the TGT session key and does not require the KDC to validate the user's password again. Rotating the user password prevents future password-based AS authentication with the old key, but it does not automatically invalidate every TGT already issued to the user.

The security distinction is:

```text
Old password can establish a new TGT
```

versus:

```text
Already-issued TGT can obtain another service ticket
```

The second remained true while the first did not.

---

## A Stale Cached Password Does Not Authenticate After Rotation

U08B-R2 tested whether the RODC's possession of a previous user key could be abused after the directory password changed.

The controlled sequence was:

1. Set `rodc_u08_user` to PRP Allow.
2. Prepopulate the current password to RODC01.
3. Confirm `RevealedOnRODC: True`.
4. Obtain a branch-authentication baseline.
5. Change the user to `DenyExplicit`.
6. Rotate the password exactly once, advancing KVNO 5 to KVNO 6.
7. Replicate the directory metadata to DC03 and RODC01.
8. Confirm `RevealedOnRODC: False`.
9. Attempt fresh authentication using the prior password.

The fresh request failed. Windows returned:

```text
0xC000006A
The user name or password is incorrect.
```

The packet capture showed RODC01 returning normal preauthentication-required behavior followed by Kerberos error 24, `KDC_ERR_PREAUTH_FAILED`. It did not accept the stale locally cached password as a valid credential for a new authentication.

The failed old-password request did not re-reveal the account, did not advance the directory KVNO, and did not reveal SRV02's machine account. This negative result closed the stale-password-authentication hypothesis.

---

## Disabled Accounts and the 20-Minute Revocation Window

The disabled-account tests used `rodc_u09_user`, whose password was allowed and revealed on RODC01.

### Fresh Enabled Baseline

U09A started from an empty ticket cache while the user was enabled. RODC01 performed the AS exchange locally and issued a branch TGT and `host/RODC01.reflect.lab` service ticket. Event 4768 on RODC01 identified service `krbtgt_570`, and the client cache showed `TGT issued by branch: 570`.

### RODC-Local Request Shortly After Disablement

The user was then disabled on DC01, and the change was replicated to DC03 and RODC01. The existing branch session was retained. Approximately four minutes after the baseline, U09B requested a previously uncached `cifs/RODC01.reflect.lab` ticket.

The request succeeded. RODC01 issued a replacement branch TGT and the CIFS ticket even though every directory server reported the account disabled. The user's `PasswordLastSet` and KVNO remained unchanged, and the secret remained revealed on RODC01.

This result matched the Windows account-revocation window. It was not an unlimited bypass. The branch TGT was still younger than the approximately 20-minute threshold at which KILE requires a new account-good-standing check for a TGS request.

### Direct RODC Request After the Window

After the branch TGT aged beyond the threshold, U09C-R1 requested a new LDAP ticket while explicitly bound to RODC01. RODC01 returned Kerberos error 18 for the attempted replacement TGT, AS exchange, and LDAP service request. Windows surfaced:

```text
0xC0000072
The referenced account is currently disabled and may not be logged on to.
```

The packet capture contained direct WS01-to-RODC01 requests and direct RODC01-to-WS01 `KDC_ERR_CLIENT_REVOKED` replies. DC03 recorded no corresponding event for the controlled request. This proved that RODC01 itself enforced account revocation after the age threshold.

---

## Hub-Required Requests Trigger Immediate Writable-DC Authority

U09D tested an important asymmetry inside the 20-minute local window. I created a fresh U09 branch session while the account was enabled, disabled the account, replicated that state, retained the young branch TGT, and requested `cifs/SRV02.reflect.lab`.

Unlike the RODC-local CIFS request in U09B, the SRV02 request required a service key not held by RODC01. The sequence was:

1. WS01 sent the SRV02 TGS request to RODC01.
2. RODC01 returned Kerberos error 7 because it could not issue the target ticket locally.
3. The client attempted the writable path through RODC01 and DC03.
4. DC03 evaluated the disabled account and returned error 18.
5. Windows surfaced `0xC0000072`.

The request occurred well inside 20 minutes, but the hub KDC had to participate and therefore applied current authoritative account state. The practical post-disablement behavior was service-dependent:

| Requested service | Key available at RODC | Under-20-minute result |
|---|---:|---|
| RODC-local service | Yes | New ticket issued locally |
| Hub-only or uncached service | No | Writable KDC evaluates disabled state and denies |

This is a meaningful operational distinction. The temporary branch continuation is not equivalent to unrestricted domain access. It is bounded by which services the RODC can satisfy locally and whether the request triggers writable-domain-controller processing.

---

## Native Windows Routing Can Obscure the Enforcing KDC

During early aged-ticket testing, the Windows client sometimes added a writable KDC entry to the binding cache even when both the short domain name and realm had been explicitly bound to RODC01. At the revocation boundary, `klist get` could fail locally, contact a writable KDC directly, or return `STATUS_NO_LOGON_SERVERS` when writable TCP and UDP port 88 were blocked.

In the first U11 controlled run, the following routing controls were applied on WS01:

- Block outbound TCP 88 to DC01 and DC03.
- Block outbound UDP 88 to DC01 and DC03.
- Leave RODC01 TCP 88 reachable.
- Bind `REFLECT` and `REFLECT.LAB` to RODC01.

The enabled baseline and six-minute replacement succeeded through RODC01. At approximately 22 minutes from baseline, native `klist get` failed with:

```text
0xC000005E
STATUS_NO_LOGON_SERVERS
```

The RODC capture contained no Stage 2 request from WS01. This did not prove that RODC01 would accept or reject the ticket. It proved that the Windows Kerberos client declined to send the decisive aged request to the partial-secret KDC and attempted to obtain writable-KDC processing instead.

This routing behavior is a client-side defense and availability characteristic, but it made a raw direct test necessary to answer the server-side question.

---

## Replacement Branch TGTs Do Not Reset Revocation Age

The strongest remaining hypothesis was a sliding-window bypass:

> If an RODC issues a replacement branch TGT before the original ticket reaches 20 minutes, does the replacement ticket receive a new revocation interval that can be refreshed repeatedly?

If true, a disabled account with an existing branch TGT might have been able to maintain branch-local access by requesting replacement TGTs before each interval expired.

### Raw Aged-TGT Control

Before testing the sliding sequence, I used a raw Kerberos client to send an already aged branch TGT directly to RODC01 at `10.10.20.16`. The request targeted:

```text
GC/RODC01.reflect.lab/reflect.lab
```

At 31.85 minutes from the original baseline and 25.56 minutes from the most recent replacement, RODC01 returned:

```text
KRB-ERROR (18): KDC_ERR_CLIENT_REVOKED
```

`RODC-U11-RAW-AGED.pcapng` contained one direct WS01-to-RODC01 TCP Kerberos request and one direct RODC01 error response. This confirmed that the raw client could reach and test RODC01 without the native Windows routing layer.

### Decisive Two-Stage Raw Test

I then reset the experiment from a clean enabled baseline:

1. Enable U09 and replicate the state to DC03 and RODC01.
2. Obtain a fresh branch TGT directly from RODC01.
3. Disable U09 immediately and replicate the state to every DC.
4. At approximately six minutes, use the baseline branch TGT to request a replacement `krbtgt/REFLECT.LAB` ticket directly from RODC01.
5. At approximately 22 minutes from baseline and 16 minutes from replacement, use the replacement ticket to request a new GC service ticket directly from RODC01.

Stage 1 succeeded:

```text
BaselineStarted     : 8/15/2026 3:50:34 AM
Stage1Started       : 8/15/2026 3:56:35 AM
MinutesFromBaseline : 6.01
TGS request         : successful
```

The replacement ticket displayed:

```text
ServiceName : krbtgt/REFLECT.LAB
StartTime   : 8/15/2026 3:56:35 AM
EndTime     : 8/15/2026 4:56:35 AM
RenewTill   : 8/22/2026 3:50:35 AM
```

Stage 2 was deliberately placed after the original 20-minute boundary but before 20 minutes had elapsed from the replacement:

```text
Stage2Started          : 8/15/2026 4:12:36 AM
MinutesFromBaseline    : 22.04
MinutesFromReplacement : 16.03
```

RODC01 returned:

```text
KRB-ERROR (18): KDC_ERR_CLIENT_REVOKED
```

The final packet capture, `RODC-U11-FINAL-RAW.pcapng`, contained:

| Capture exchange | Relative timing | Result |
|---|---:|---|
| Enabled baseline AS and host TGS | T+0 | Branch TGT and host ticket issued |
| Direct `krbtgt/REFLECT.LAB` TGS request | T+6 minutes | TGS-REP, replacement branch TGT issued |
| Direct GC TGS request using replacement | T+22 minutes | KRB-ERROR 18 |

Every decisive exchange was between WS01 `10.10.20.20` and RODC01 `10.10.20.16`. No writable KDC participated in either raw stage.

The SHA-256 hash of the final capture was:

```text
D3486F0B6FDE8F8B05F1316ED1576B96D11A09DE2C9961A3DC78781526C69EF0
```

### Interpretation

The replacement ticket's visible `StartTime` did not establish a new revocation interval. RODC01 enforced revocation based on the age of the original authentication lineage. The exact internal field cannot be proven from the encrypted ticket body alone, but Kerberos `authtime` is the most likely protocol-level anchor. The important functional result does not depend on naming the internal field:

```text
Replacement TGT issued at T+6
        |
        v
Replacement appears only 16 minutes old at final request
        |
        v
Original authentication is 22 minutes old
        |
        v
RODC returns KDC_ERR_CLIENT_REVOKED
```

Repeated replacement branch TGTs therefore cannot indefinitely extend disabled-account access.

---

## Results Summary

| Test | Controlled state | Result |
|---|---|---|
| M02 | WS01 machine authentication through RODC | Branch machine TGT issued; uncached service required hub behavior |
| U01/U01B | User secret already cached | Local RODC AS and TGS; branch 570 TGT |
| U02A/U02B | User allowed but initially uncached | First path forwarded and secret cached; later path local |
| U03A/U03B | User denied and uncached | Writable KDC required; secret did not become locally usable |
| U04A | Cached-user control | Local branch authentication succeeds |
| U04B/U04C | Denied user with writable KDC unavailable | `KDC_ERR_SVC_UNAVAILABLE` |
| U05 series | Branch and hub routing | Native session can hold branch PRIMARY and HUB-PRIMARY TGTs |
| U06A-R1 | Cached user requests service whose key is not on RODC | Initial error 7, hub fallback succeeds; service secret remains unrevealed |
| U06B | Cached HTTP service account | RODC issues service ticket locally |
| U06C | Cached service changed to `DenyExplicit`, no rotation | Local issuance still succeeds |
| U06D | Denied cached service password rotated | Local stale key unusable; hub fallback succeeds |
| U07A | User Allow and revealed | Local branch authentication |
| U07B | User changed to `DenyExplicit`, secret still revealed | Local branch authentication still succeeds |
| U07C-R1 | Denied user password rotated | Reveal state clears; AS and TGS forwarded to DC03 |
| U08A | Pre-rotation branch TGT retained after password rotation | TGT remains usable for local service-ticket issuance |
| U08B-R2 | Attempt new authentication with old cached password | `KDC_ERR_PREAUTH_FAILED`; stale password not accepted |
| U09A | Enabled and revealed user | Fresh branch TGT and service ticket |
| U09B | Disabled user, branch-local request under 20 minutes | Replacement branch TGT and new local service ticket issued |
| U09C-R1 | Disabled user, direct RODC request after 20 minutes | `KDC_ERR_CLIENT_REVOKED` from RODC01 |
| U09D | Disabled user under 20 minutes, hub-required service | Writable KDC checks account and rejects immediately |
| U11A native | Writable KDC blocked at aged boundary | Native client returns no-logon-servers without sending decisive request to RODC |
| U11 raw aged | Aged TGT sent directly to RODC | `KDC_ERR_CLIENT_REVOKED` |
| U11 final raw | Replacement at T+6, direct request at T+22/Treplacement+16 | `KDC_ERR_CLIENT_REVOKED`; no sliding bypass |

---

## Security and Operational Implications

### PRP Denial Is Not Immediate Secret Revocation

Removing an account from an RODC's allowed list or adding it to the denied list should not be treated as an immediate purge of a secret already cached at that branch. In testing, the account continued authenticating locally while the cached key remained current. This matters if an administrator changes PRP in response to a suspected RODC compromise or realizes that a sensitive account was mistakenly cached.

The effective remediation boundary was a password change, not the PRP change alone. The PRP change prevented the new password generation from being revealed after rotation.

### Password Rotation Does Not Revoke Existing Tickets

Password rotation prevented the old password from establishing a new TGT, but an already-issued branch TGT remained useful until normal ticket or account-revocation rules stopped it. Responders should therefore distinguish credential containment from ticket invalidation. Rotating a password addresses future password-based authentication but does not guarantee that every active Kerberos session immediately disappears.

### Disabled-Account Continuation Is Locally Bounded

A recently disabled account can continue obtaining new branch-local tickets during the documented revocation interval. However, access is constrained by the RODC's local secrets. Requests requiring a writable KDC receive current account-state enforcement immediately. The branch exposure is therefore determined by the intersection of:

- the account's already-issued branch ticket material,
- the remaining revocation interval,
- the service secrets available to the RODC,
- and whether the client can reach a writable KDC.

### The Sliding Extension Hypothesis Was Rejected

The most severe potential outcome would have been indefinite access through repeated branch-TGT replacement. The direct raw test rejected that hypothesis. The RODC preserved the original authentication age and enforced account revocation even though the replacement ticket was visibly younger than 20 minutes.

### Native Windows Adds a Second Control Layer

The Windows Kerberos client did not always send an aged branch request to the RODC. Once validation became due, it could seek a writable KDC. This behavior reduced the chance that a normal client would rely only on stale branch-local state, but it also created an availability dependency. With writable KDCs blocked, the client returned `STATUS_NO_LOGON_SERVERS` even though RODC01 remained reachable.

---

## Defensive Guidance

PRP should be treated as a placement policy for secrets, not a retroactive revocation mechanism. If an account was mistakenly or unnecessarily cached on an RODC, defenders should first change its resultant PRP to deny replication, then rotate the account password. The PRP change prevents the new key generation from being replicated, while the password rotation makes the previously cached key stale.

For a user account, a practical containment sequence is:

1. Remove the account from the RODC allowed list.
2. Add it to the RODC denied list if explicit denial is appropriate.
3. Force directory replication so the RODC sees the PRP change.
4. Rotate the password.
5. Replicate the new password metadata to the writable partner and RODC.
6. Verify the new KVNO on each directory server.
7. Verify `DenyExplicit` and confirm the account is no longer currently revealed.

Service and computer accounts require the same key-lifecycle reasoning, but rotation may affect running services or secure channels and must be planned accordingly.

Disabling an account is still valuable, but responders should not assume that it instantly invalidates existing Kerberos tickets. Microsoft documents a short account-revocation interval for TGS processing. Requests that can be completed entirely by the branch may continue briefly, while hub-required requests can be denied earlier by the writable KDC. Existing service tickets may also remain usable at application servers without another KDC exchange.

Finally, KDC binding output alone is not sufficient to attribute a decision. Capture both sides of the RODC path or correlate events from RODC01 and its writable partner. `Kdc Called: RODC01` identifies the client's contacted KDC, but the RODC may still have forwarded authoritative processing to a writable DC.

---

## Root Cause Discussion

I want to separate directly observed behavior from implementation inference.

The observed behavior is clear:

- PRP denial did not erase an already current cached key.
- Password rotation advanced the account KVNO and ended local use of that key generation.
- Already-issued branch TGTs remained usable independently of password rotation.
- Disabled-account service-ticket issuance continued locally for a short interval.
- Writable participation caused current account state to be applied immediately.
- After the revocation interval, RODC01 itself rejected the disabled user.
- A replacement branch TGT did not restart that interval.

The likely design explanation is that PRP is consulted when deciding whether a secret may be replicated, while Kerberos ticket validation and account revocation use their own ticket and account-policy lifecycles. The replacement-TGT result strongly indicates that the revocation age is tied to the original authentication lineage rather than the replacement's visible start time. Kerberos `authtime` is a likely anchor, but confirming the exact internal implementation would require ticket decryption with the relevant RODC key or source-level visibility.

---

## Specification Alignment and Novelty Assessment

Most of the final behavior aligns with Microsoft's public protocol documentation:

- Microsoft describes RODCs as using separate `krbtgt` keys and PRP-governed secret caching.
- MS-KILE documents branch-aware TGS processing and writable-DC fallback when the RODC lacks a required service secret.
- MS-KILE documents account-good-standing checks for disabled, expired, locked, and logon-hours-restricted accounts.
- Microsoft states that Windows KDCs check account revocation when a TGT is older than approximately 20 minutes.

The research value is therefore not a claim that the documented 20-minute window itself is a new vulnerability. The useful contribution is the end-to-end empirical map across PRP changes, current reveal state, key rotation, branch and hub ticket caches, service-key availability, native client routing, and replacement-TGT behavior.

The strongest potential vulnerability hypothesis was the sliding replacement-TGT extension. The decisive raw test disproved it. I would not currently submit this result to MSRC as a security-boundary bypass. It is better positioned as implementation research and defensive guidance.

---

## Evidence Artifacts

The principal captures retained from the research include:

- `RODC-U01.pcapng` and `RODC-U01B.pcapng`: cached-user baseline
- `RODC-U02A.pcapng` and `RODC-U02B.pcapng`: allowed uncached user and later local caching
- `RODC-U03A.pcapng` and `RODC-U03B.pcapng`: denied-user writable forwarding
- `RODC-U04B.pcapng` and `RODC-U04C.pcapng`: denied-user failure without writable processing
- `RODC-U06A-R1.pcapng`: uncached service and hub fallback
- `RODC-U06B.pcapng`, `RODC-U06C.pcapng`, and `RODC-U06D.pcapng`: service-secret PRP and rotation lifecycle
- `RODC-U07A.pcapng`, `RODC-U07B.pcapng`, and `RODC-U07C-R1.pcapng`: user-secret PRP and rotation lifecycle
- `RODC-U08A.pcapng`: retained branch TGT after password rotation
- `RODC-U08B-R2-WS01.pcapng`: failed authentication with stale password
- `RODC-U09A.pcapng`, `RODC-U09B.pcapng`, `RODC-U09C-R1-WS01.pcapng`, and `RODC-U09D.pcapng`: disabled-account lifecycle
- `RODC-U11A-R1.pcapng`: native-client controlled-routing test
- `RODC-U11-RAW-AGED.pcapng`: direct aged-TGT control
- `RODC-U11-FINAL-RAW.pcapng`: decisive replacement-TGT test

Important final-capture hash:

```text
RODC-U11-FINAL-RAW.pcapng
SHA256 D3486F0B6FDE8F8B05F1316ED1576B96D11A09DE2C9961A3DC78781526C69EF0
```

Ticket-export files created for the raw test were deleted after validation, the target logon session was purged, test firewall controls were removed, and the research account was cleaned up after the final capture.

---

## Disclosure and Research Timeline

At the time of writing, I have not submitted this RODC research to MSRC as a separate vulnerability report. The behavior observed during the account-revocation tests is consistent with the documented Windows KILE revocation interval, and the strongest potential bypass, repeated replacement of the branch TGT to create a sliding interval, was rejected by RODC01. Unless additional evidence establishes a security-boundary violation, I consider this implementation research rather than a vulnerability disclosure.

The high-level research timeline was:

- **August 14, 2026**: RODC topology, replication health, machine-account behavior, and cached, uncached, and denied-user baselines validated.
- **August 14, 2026**: Branch-versus-hub routing and uncached-service behavior captured.
- **August 14, 2026**: User and service PRP transitions tested before and after password rotation.
- **August 14-15, 2026**: Retained branch-TGT and stale cached-password hypotheses tested.
- **August 15, 2026**: Disabled-account behavior tested below and above the 20-minute revocation interval.
- **August 15, 2026**: Native Windows routing behavior isolated with explicit KDC bindings and writable-KDC firewall controls.
- **August 15, 2026**: Raw aged-TGT control and decisive replacement-TGT sliding-window test completed.
- **August 15, 2026**: Final capture validated, sensitive ticket artifacts removed, and lab cleanup completed.

---

## References

- Microsoft, [Active Directory default accounts: RODCs and the KRBTGT account](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts)
- Microsoft Open Specifications, [MS-KILE: Read-only Domain Controller](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/14ecbc26-73ed-40f8-b8fd-0140e715e1c8)
- Microsoft Open Specifications, [MS-KILE: TGS Exchange](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2c42487d-2572-4090-999d-0a2d73d8c946)
- Microsoft Open Specifications, [MS-KILE: Key Version Numbers](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/31411d28-7ad5-4237-a1f9-50738a08aa82)
- Microsoft Open Specifications, [MS-KILE: Account Revocation Checking](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/519392b1-625a-420d-be90-d588c852dda3)
- Microsoft Open Specifications, [MS-KILE: Check Account Policy for Every Session Ticket Request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e19be8b8-9130-40a4-9cd1-92d0cbd46a51)
- Microsoft, [Repadmin /rodcpwdrepl](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742095%28v%3Dws.11%29)

---

## Conclusion

The original question behind this research was broader than whether an RODC could authenticate a cached user. I wanted to understand which security decisions followed live directory state, which followed cached keys, which followed already-issued tickets, and where writable-domain-controller authority re-entered the path.

The answer is a layered lifecycle. Password Replication Policy controls whether a secret generation may be placed on the RODC, but changing PRP does not purge a secret that is already current and cached. Password rotation ends the usefulness of that old key for new password authentication, but it does not automatically revoke branch TGTs already issued to the user. A recently disabled account can continue receiving some branch-local tickets during the documented revocation interval, while services requiring hub participation are subject to current writable-DC account state. Once the original authentication age exceeds approximately 20 minutes, RODC01 enforces revocation itself.

The final replacement-TGT experiment closed the most important open question. A new branch TGT issued six minutes into the interval did not establish a new 20-minute revocation window. At 22 minutes from the original authentication and only 16 minutes from the replacement, RODC01 returned `KDC_ERR_CLIENT_REVOKED`. The RODC retained the original authentication-age boundary, preventing an indefinite sliding extension.

The broader takeaway is that RODC security behavior cannot be understood from PRP, ticket timestamps, or KDC bindings in isolation. Reliable analysis requires correlating the current directory object, the revealed-secret generation, the branch and hub ticket caches, service-key availability, client routing, and packet-level KDC participation. When those layers are separated, the implementation behaves consistently and the apparent contradictions resolve into distinct key, ticket, and revocation lifecycles.
