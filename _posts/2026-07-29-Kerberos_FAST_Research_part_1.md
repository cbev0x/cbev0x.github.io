---
title: "Kerberos FAST Armoring: What It Is and How Enforcement Actually Works"
date: 2026-07-29
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, FAST, Research]
published: true
---

This is part one of a two-part series on Kerberos FAST armoring. Part one covers
the protocol mechanics and how enforcement behaves at the AS and TGS layers. Part
two covers the tool I built to test all of this -- SteadFAST -- along with the
empirical findings against a fully patched Windows Server 2025 environment.

## What is FAST?

FAST stands for Flexible Authentication Secure Tunneling. It is defined in
[RFC 6113](https://www.rfc-editor.org/rfc/rfc6113) and describes a way to wrap
a Kerberos AS-REQ or TGS-REQ inside an encrypted tunnel keyed off a
pre-existing ticket -- typically a machine account TGT. The goal is to protect
the user's pre-authentication data from offline attack. In a standard (unarmored)
AS-REQ, the PA-ENC-TIMESTAMP padata is encrypted with the user's long-term key
and goes out on the wire in the clear. If you capture it, you can crack it
offline. FAST puts a second layer of encryption around the whole exchange so an
observer sees only ciphertext derived from the armor ticket's session key, not
anything tied to the user's password.

Microsoft implemented FAST under the name "Kerberos armoring" and shipped it in
Windows Server 2012 / Windows 8. You will see both names used interchangeably. In
practice the terms are synonymous: armoring is Microsoft's name for the FAST
mechanism as implemented in MS-KILE.

## How armoring works mechanically

Before a user can send an armored AS-REQ, a machine account obtains its own TGT
unarmored (machine account AS-REQs are the one class that remains unarmored even
in enforced environments, because there is no prior credential to bootstrap from).
That TGT and its session key become the armor source.

The client then derives an armor key using the RFC 6113 `KRB-FX-CF2` function:

```
armor_key = KRB-FX-CF2(subkey, tgt_session_key, "subkeyarmor", "ticketarmor")
```

where `subkey` is a fresh random key generated per-request. The actual user
pre-authentication data -- the PA-ENC-TIMESTAMP or, in an armored TGS-REQ, the
authenticator -- is encrypted inside a PA-FX-FAST padata element keyed with this
armor key. The outer AS-REQ/TGS-REQ body remains structurally normal; only the
padata payload is replaced with the FAST wrapper.

On the wire you can tell an armored request by the PA-FX-FAST padata type (136).
Inside it you find an `armor` field carrying an AP-REQ for the armor TGT and an
`enc-fast-req` containing the actual request content. The KDC decrypts the armor,
verifies the AP-REQ, derives the same armor key, decrypts the inner request, and
processes it normally.

## Enforcement levels

Windows exposes four enforcement states via the KDC group policy ("KDC support
for claims, compound authentication and Kerberos armoring"):

| Level | GPO name | Behavior |
|---|---|---|
| 0 / not configured | Off | FAST not offered; unarmored accepted |
| 1 | Supported | FAST offered; unarmored still accepted |
| 2 | Always provide claims | Same as level 1 for most scenarios; claims always included |
| 3 | Fail unarmored authentication requests | Unarmored AS-REQ or TGS-REQ rejected |

Levels 1 and 2 are indistinguishable from a client's perspective: both accept
unarmored requests. Only level 3 -- S3 in the testing I describe in part two --
actually enforces armoring. When S3 is active and a client sends an unarmored
AS-REQ, the KDC returns `KDC_ERR_POLICY` immediately. The client can then retry
with armor if it has a machine TGT available.

The enforcement is configured DC-side at:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters
EnableCbacAndArmor = 1 (DWORD)
CbacAndArmorLevel  = 3 (DWORD)
```

One gotcha I found in the lab: the `\Parameters` subkey is required. Writing
directly under `...\System\KDC` without the `\Parameters` child key has no effect.
The reliable way to flip the level is via Group Policy Editor and `gpupdate /force`.

Domain Functional Level matters too: below DFL 2012, the fail-unarmored behavior
is silently ignored even if the registry key says 3. In a Windows Server 2025
domain this is not a concern, but it is worth knowing if you are testing in a
mixed or older environment.

## What the AS exchange looks like under S3

Under S3 enforcement an unarmored AS-REQ gets a clean `KDC_ERR_POLICY` error
with a `PA-FX-FAST` offer in the error data -- the KDC is telling the client
what it expects. An armored AS-REQ gets a `PA-FX-FAST` PREAUTH-REQUIRED response
on the first round (with the enc-fast-rep containing the cookie), followed by the
full armored AS-REQ with the PA-ENCRYPTED-CHALLENGE (preauth type 138), followed
by the AS-REP.

The preauth type is the easiest detection signal. A normal unarmored AS-REQ shows
preauth type 2 (PA-ENC-TIMESTAMP). An armored one shows type 138
(PA-ENCRYPTED-CHALLENGE). Event ID 4768 logs both; the difference is in the
PreAuthType field.

## What the TGS exchange looks like under S3

This is where enforcement behavior diverges from what most documentation describes
and what I found to be undocumented: the TGS refusal under S3 is not a clean
`KDC_ERR_POLICY`.

When a client sends an unarmored TGS-REQ under S3 fail-unarmored, the KDC
returns a **zero-length record** -- `Record Length: 0`, `BER Empty choice was
found` in Wireshark -- not a Kerberos error at all. The client gets no usable
response and hangs. I confirmed this against both user accounts and machine
accounts (the machine account exemption applies only to the AS exchange, not the
TGS), and I confirmed it cross-client: impacket's own unarmored TGS-REQ under S3
draws the identical zero-length record.

The likely reason is that the TGS code path cannot FAST-wrap an error without an
armor context to wrap it in, so it falls back to returning nothing. The AS path
does not have this problem because the `PA-FX-FAST` offer in the error data is
unencrypted. This asymmetry -- clean `KDC_ERR_POLICY` at the AS, empty record at
the TGS -- means that unarmored tools hang rather than failing gracefully when
they try to request a service ticket in a fail-unarmored domain. Part two covers
what that means operationally.

## Samba's model

For completeness: Samba 4.24 supports FAST armoring (via its Heimdal snapshot)
and advertises it with `kdc enable fast = Yes` in smb.conf. However, Samba has
no equivalent of Windows' graduated `CbacAndArmorLevel` switch. There is no
"fail unarmored" mode at the domain level. The only way to require armoring on
Samba is through per-account Authentication Policies, which require Domain
Functional Level 2016. At FL 2008R2 -- the level my test Samba domain runs at --
armoring is offered but never enforced, and there is no knob to change that.

This is the core cross-implementation difference: Windows enforces armoring with a
global domain switch; Samba expresses it through per-principal access-check
policies. The consequence for the empty-reply finding is clean: since Samba has
no fail-unarmored TGS path, it cannot produce that zero-length record. The
behavior is Windows-specific by construction.

## What FAST does and does not protect

A few things worth stating plainly:

**What it protects:** The user's pre-authentication data (the PA-ENC-TIMESTAMP or
PA-ENCRYPTED-CHALLENGE exchange) is encrypted inside the armor tunnel. An offline
observer cannot extract the user's long-term key material from the AS-REQ. It also
provides signed KDC errors, which mitigate error-spoofing and certain downgrade
attacks.

**What it does not protect by itself:** A service ticket obtained via AS-REQ
(not a TGS-REQ) -- which I cover in part two -- bypasses the TGS exchange
entirely. The armoring protects the credential exchange, not the roasting attack
surface that exists in the issued ticket's encrypted portion.

**RC4 armor is refused on WS2025:** When I tested with an NT hash as the armor
credential, the KDC returned `KDC_ERR_ETYPE_NOSUPP`. The DC will not issue an
RC4-encrypted armor TGT. This means an attacker cannot force the FAST exchange
down to RC4 even if they have only an NT hash for the armor account. AES256 is
the required armor etype in practice.

---

Part two covers SteadFAST, the tool I built to test all of this, along with the
empirical findings matrix, the armored delegation capability, the Scapy bug I
found and fixed, and the telemetry side-by-sides.
