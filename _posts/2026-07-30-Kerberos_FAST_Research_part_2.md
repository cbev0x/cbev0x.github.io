---
title: "SteadFAST: Armored Kerberos Offensive Tooling for Fail-Unarmored Domains"
date: 2026-07-30
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, FAST, Research]
published: true
---

This is part two of a two-part series on Kerberos FAST armoring. Part one covered
the protocol mechanics and how enforcement behaves at the AS and TGS layers. This
post covers SteadFAST, the tool I built to test all of this, the empirical
findings matrix against a fully patched Windows Server 2025 environment, and the
armored delegation capability that motivated building it.

**Authorized use only.** SteadFAST is built for penetration testing and research
against systems you have explicit permission to test. The primitives it implements
mirror what impacket, Rubeus, and NetExec do -- request service tickets, request
AS-REP hashes, and perform constrained delegation -- the difference is that it
armors the requests so they work when standard tools do not.

Repo: [github.com/cbev0x/SteadFAST](https://github.com/cbev0x/SteadFAST)

---

## Why build another tool?

The short answer is that existing tooling breaks silently under S3 fail-unarmored
enforcement. If you try to request a service ticket with impacket's `GetUserSPNs`
or `getST` in a domain where CbacAndArmorLevel is 3, you get a blank error or a
hang, not a clean failure. Rubeus has the same problem for its non-LSASS code
paths. [TrustedSec documented this clearly](https://trustedsec.com/blog/i-wanna-go-fast-really-fast-like-kerberos-fast).

The only public tool that addresses this is
[BreakFAST](https://github.com/monsieurPale/BreakFAST) by monsieurPale, which
arms a TGT request and a plain TGS request under enforcement. SteadFAST builds on
that foundation, adds a complete subcommand structure, and extends it into
delegation.

---

## Architecture

SteadFAST is built on Scapy's native Kerberos layer rather than on impacket.
Scapy implements FAST natively -- it handles the PA-FX-FAST construction,
armor-key derivation via KRB-FX-CF2, and the full armored AS-REQ/TGS-REQ
exchange without any modification. impacket is used only as a ccache interop
layer (via its CCache.fromKRBCRED path) and as an offline oracle for
cross-checking hash output. All `.py` files are kept pure ASCII for Windows
PowerShell 5.1 compatibility.

Commands follow a Certipy/NetExec-style subcommand structure:

```
python -m steadfast posture     # fingerprint enforcement level
python -m steadfast roast       # armored AS-requested ST (Kerberoast without a TGT)
python -m steadfast asreproast  # no-preauth AS-REP roast under enforcement
python -m steadfast delegate    # delegation under FAST (--s4u2proxy / --probe)
python -m steadfast inspect     # offline ccache analysis -- flags + PAC signatures
```

Every command takes short and long flags (-v/--verbose, --debug, --timeout),
a consistent armor source group (--armor-user, --armor-password, --armor-hashes,
--armor-aes-key), and outputs aligned fields to stdout with a `[+]` summary line.

---

## The test environment

All empirical findings are against a fully patched Windows Server 2025 domain
(reflect.lab). The lab topology: DC01 (.10) as the enforcement target and armor
source, SRV02 (.12) as the delegation hop, DC02 (.13) as the second DC for
cross-DC consistency testing, and Kali (.50) running the tool. FAST enforcement
is set via Group Policy (System > KDC > Support for claims, compound
authentication, and Kerberos armoring) with CbacAndArmorLevel = 3.

A computer account `fakepc$` created via `New-ADComputer` serves as the armor
source. Its AES256 key is known (derived from its password), which lets me armor
requests without extracting anything from LSASS.

---

## Findings: what enforcement actually covers

### posture: the four-state fingerprint

The `posture` command runs three legs (unarmored AS-REQ, armor TGT, armored
AS-REQ) and maps them to one of four states:

- S0: FAST not offered; both legs succeed unarmored
- S1: Supported; unarmored accepted, FAST offered
- S2: Always-provide-claims; indistinguishable from S1 at the AS layer
- S3: Fail-unarmored; unarmored returns KDC_ERR_POLICY, armored succeeds

S1 and S2 are actually indistinguishable from the wire on an unmodified AS-REQ.
The output reflects this honestly with a "cannot distinguish level 1 vs 2" caveat
rather than asserting a level it cannot confirm.

The enforcement recipe has one gotcha: the KDC registry path requires the
`\Parameters` subkey. Writing directly under `...\System\KDC` has no effect.
The reliable flip is Group Policy Editor + `gpupdate /force`.

### C2: armored Kerberoasting still works

Under S3, an armored AS-REQ with a service account SPN in the sname field returns
a service ticket from the AS exchange, not the TGS exchange. The ticket is
encrypted with the service account's long-term key, so it is crackable offline.
The `roast` command requests this AS-requested ST under armor and produces a
`$krb5tgs$18$` hash for hashcat (-m 19700) or john.

This is a re-validation of the primitive documented by Charlie Clark and Semperis.
SteadFAST's contribution here is a clean implementation that does it from a
non-domain-joined Linux host without touching LSASS, confirmed crackable on WS2025.

### C3: no unarmored holes in the AS exchange

Across tested SPNs and principal types, every unarmored AS-REQ leg under S3
returns KDC_ERR_POLICY. The sweep found zero unarmored exceptions. The
DONT_REQ_PREAUTH path (`asreproast`) is also covered: under S3, a no-preauth
AS-REQ for svc-nopreauth returns KDC_ERR_POLICY rather than an AS-REP. Enforcement
at the AS layer is comprehensive on WS2025.

### C4: the empty TGS reply

The TGS behavior under S3 is the one finding I am not aware of being documented
elsewhere. When a client sends an unarmored TGS-REQ under S3 fail-unarmored, the
KDC does not return KDC_ERR_POLICY. It returns a **zero-length Kerberos record**
-- `Record Length: 0`, "BER Empty choice was found" in Wireshark -- and the client
hangs. This applies uniformly to user accounts and machine accounts (the machine
account exemption is AS-only). I confirmed it cross-client: impacket's own
unarmored TGS-REQ at S3 draws the same zero-length record.

```
Frame 6: Kerberos
    Record Mark: 0 bytes
        Record Length: 0
    BER Error: Empty choice was found
        [Expert Info (Warning/Malformed): BER Error: Empty choice was found]
```

The probable reason is that the TGS code path cannot FAST-wrap an error without
an armor context. The AS path can embed an unencrypted PA-FX-FAST offer in a
KDC_ERR_POLICY; the TGS path has no equivalent because the error would need to be
wrapped in the same armor the client did not provide. The result is that clients
hang instead of failing gracefully -- which is directly relevant to delegation, as
I explain below.

For the cross-implementation dimension: Samba 4.24's KDC has no fail-unarmored
mode at all (its FAST setting is a boolean `kdc enable fast = Yes`, not a
graduated enforcement level), so it cannot produce this zero-length reply. The
empty record is confirmed Windows-specific by the config-model differential alone.

### A4: cross-DC consistency

Posture against DC02 (.13) at S3 returns an identical "FAST ENFORCED
(fail-unarmored) [confirmed]" verdict to DC01. The GPO applies domain-wide;
no per-DC drift.

### B2: user TGTs as armor

RFC 6113 permits any TGT as armor, not just machine account TGTs. Under S1, the
KDC accepts a user's TGT as a FAST armor source. The practical ceiling is
unchanged: users cannot obtain an unarmored TGT at S3 in the first place, so
machine accounts remain the only usable armor source when enforcement is on.

### E1/E3: detection telemetry

The armored AS-requested ST route avoids the 4769 (TGS-REQ) event entirely. It
logs instead as a **4768** (Kerberos Authentication Ticket Requested) with
ServiceName set to the service account rather than krbtgt. The FAST tell in the
event data is PreAuthType **138** (PA-ENCRYPTED-CHALLENGE), versus type 2
(PA-ENC-TIMESTAMP) for an unarmored unarmored request.

This is prior art from Clark/Semperis (the 4768-not-4769 blind spot) and from
Microsoft's own event documentation (type 138). SteadFAST produces the exact
event sequence for a clean side-by-side: run a standard Kerberoast alongside an
armored AS-requested-ST roast and compare the event streams. The armored roast
leaves no 4769.

### RC4 armor refused

When passing an NT hash as the armor credential, WS2025 returns
KDC_ERR_ETYPE_NOSUPP. The DC will not issue an RC4-encrypted armor TGT. An
attacker cannot force the armored exchange down to RC4 even with only an NT hash
for the armor account.

---

## Armored delegation under enforcement

The empty TGS reply finding has a direct operational consequence: impacket's
`getST` and Rubeus perform **unarmored** TGS-REQs for their S4U2self and S4U2proxy
legs. Under S3 fail-unarmored, those TGS-REQs draw the zero-length reply and the
tools hang without producing a ticket. They cannot perform constrained delegation
or RBCD abuse in a fail-unarmored domain.

SteadFAST's `delegate --s4u2proxy` resolves this by arming both TGS legs.

```bash
python -m steadfast delegate --s4u2proxy \
    -u 'fakepc$' -p 'Password123!' \
    --armor-password 'Password123!' \
    --impersonate Administrator \
    -s cifs/srv02.reflect.lab \
    -d reflect.lab --dc-ip 10.10.20.10 \
    --save admin.ccache
```

The chain, all FAST-armored under S3:

1. fakepc$ obtains its armor TGT (unarmored AS-REQ -- the machine account bootstrap)
2. Armored S4U2self: KDC issues a forwardable ST for `host/fakepc.reflect.lab` as
   Administrator
3. Armored S4U2proxy: that ST is used as evidence to obtain `cifs/srv02` as
   Administrator
4. The ccache is saved; `KRB5CCNAME=admin.ccache nxc smb srv02.reflect.lab -k
   --use-kcache` authenticates as Administrator (Pwn3d!)

RBCD setup used: `fakepc$` added to SRV02's `msDS-AllowedToActOnBehalfOfOtherIdentity`.

I also confirmed the classic KCD variant (protocol transition via
`TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo`) using `svc-test` with
its `MSSQLSvc/test.reflect.lab:1433` SPN. Same chain, same result.

Prior-landscape check: BreakFAST (monsieurPale) is the only public tool that armors
Kerberos requests from a non-domain-joined Linux host. It handles armored TGT,
armored plain TGS-REQ, and the AS-requested ST primitive. It does not implement
S4U2self or S4U2proxy; its README lists "delegation related vectors" as future
work. impacket and Rubeus (non-LSASS paths) cannot do this under enforcement.
**Armored S4U2self -> S4U2proxy/RBCD is, to my knowledge, not implemented in any
other public tool.**

---

## The Scapy FAST x S4U2self bug

Building the armored S4U2self leg surfaced a legitimate bug in Scapy 2.7.0's Kerberos
implementation, which is worth documenting separately because it affects anyone
who tries to do FAST-armored S4U2self with Scapy.

Under FAST, Scapy's `KerberosClient.tgs_req` generates a random authenticator
subkey and uses it as the reply key (this is correct per RFC 6113). The
PA-S4U-X509-USER padata carries the flag `USE_REPLY_KEY_USAGE`, which means the
KDC verifies its checksum using the **reply key** -- the subkey. But Scapy
computes that checksum against `self.key` (the raw TGT session key) instead of
`self.subkey`. Unarmored, there is no subkey so the reply key equals the TGT
session key and the checksum is valid. Armored, the reply key is the subkey, so
the KDC rejects the checksum with `KRB_AP_ERR_MODIFIED (41)`.

The fix is a runtime source-patch in `lib/_scapy_fast_s4u_patch.py`. It re-keys
only the PA-S4U-X509-USER checksum to `self.subkey or self.key`, leaving the
PA-FOR-USER checksum (which correctly uses the raw session key at HMAC-MD5/-138)
and the authenticator checksum unchanged. The patch is version-guarded against
Scapy 2.7.0 and applied at the top of `delegate.run()`. It will be submitted
upstream to [secdev/scapy](https://github.com/secdev/scapy).

---

## The inspect command and the Bronze-Bit question

`inspect` is a read-only offline lens for ccache files. It decodes ticket flags
(forwardable, renewable, initial, etc.) and, given the service account's key,
decrypts the ticket enc-part and lists the PAC buffers -- including whether PAC
buffer 0x10 (the Ticket Signature, the CVE-2020-17049 anti-Bronze-Bit fix) is
present.

```bash
python -m steadfast inspect asreq-st.ccache \
    --service-key 6f4650058d111f6794caab1b17281c6eb8a0290a1395a11a96402a8f88692779 \
    --etype 18
```

```
[*] ticket 0: jdoe@REFLECT.LAB -> fakepc$@REFLECT.LAB
    flags      : forwardable renewable initial pre_authent enc_pa_rep   [forwardable]
    etype      : 18
    PAC buffers: 0x01 Logon Info, 0x06 Server Checksum, 0x07 KDC (privsvr) Checksum,
                 0x0a Client Info, 0x0c UPN/DNS Info, 0x0d Client Claims,
                 0x10 Ticket Signature, 0x13 Extended KDC Signature
    Ticket Signature (0x10): PRESENT
```

Charlie Clark's AS-requested-ST writeup noted that AS-requested STs lacked the
Ticket Checksum (0x10), which was the CVE-2020-17049 (Bronze-Bit) guard added to
S4U2self evidence tickets. That observation was the basis for a potential
hypothesis: could you take an armored AS-requested ST, flip its forwardable flag
Bronze-Bit-style, and use it as evidence in an armored S4U2proxy?

The `inspect` result closes that question for WS2025: armored AS-requested STs
**carry the full modern signature set** -- 0x06 Server Checksum, 0x07 KDC
Checksum, 0x10 Ticket Signature, 0x13 Extended KDC Signature. Flipping the
forwardable flag and re-signing only 0x06 (with a key you control) would still
leave 0x07 and 0x10 stale, both keyed with krbtgt. Whatever checksum-absence
Clark observed was present in an earlier version of the server; on a current
patched WS2025 DC, the defense is in place. That is a worth-knowing re-validation:
armoring does not strip the ticket checksum, and the anti-Bronze-Bit signature is
present on both AS-requested and normal TGS-obtained tickets.

---

## Prior art and credits

- Charlie Clark / Semperis: the AS-requested service ticket primitive, the
  4768-not-4769 detection blind spot
- BreakFAST (monsieurPale): armored TGT + armored plain TGS-REQ + the
  AS-requested ST implementation in Python; the only prior art for FAST armoring
  from a non-domain-joined host. SteadFAST overlaps with BreakFAST on those three
  capabilities and credits it directly.
- Tim Medin: the original Kerberoasting primitive
- Will Schroeder: AS-REP roasting
- TrustedSec / Andrew Schwartz: the empirical documentation of impacket and
  non-LSASS Rubeus breaking under enforcement
- Steve Syfuhs: the FAST internals writeup

---

## What is coming in v1.1

The detection pack (Sigma/KQL/Get-WinEvent rules for the armored-roast 4768 +
PreAuth 138 pattern, the 4769 bypass, and the empty-reply hang) will ship
alongside a detection-focused section added to this post. Anonymous PKINIT armor
-- bootstrap the armor source with no credentials via an anonymous DH exchange --
is the one capability BreakFAST also flagged as future work; that lands in v1.1.
