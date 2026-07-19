---
title: "Testing the Windows Server 2025 PKINIT Algorithm-Agility Downgrade Surface"
date: 2026-07-19
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, PKINIT, Cryptography, Research]
published: true
---

PKINIT gained real cryptographic agility over the last few years. RFC 8636 added
key-derivation negotiation, RFC 8070 added freshness, and Microsoft's MS-PKCA
added a stronger request-body checksum. New negotiation always raises the same
question for an offensive researcher: can any of it be downgraded? We built the
tooling to manipulate every one of those elements and tested the downgrade
surface on a clean Windows Server 2025 domain controller.

The surface held. Across KDF negotiation, the request-body checksum, the legacy
request format, the CMS signing digest, the MS-PKCA PAChecksum2 extension, and
the RSA reply mode, we found no way to weaken the exchange that the KDC did not
correctly reject or that is not already documented as intended. This post is the
cleaned-up findings report: the mechanism, the method, each experiment, and the
detection telemetry that fell out of it. The tooling is released as
[pkinit-agility](https://github.com/cbev0x/pkinit-agility).

## Why the standard stack could not test this

The reason nobody had characterized this surface is tooling. The offensive
PKINIT stack that everyone uses (minikerberos, then PKINITtools, then Certipy)
models only the RFC 4556 happy path. Its AuthPack cannot carry `supportedKDFs`,
its DHRepInfo cannot parse the reply `kdf`, and it has no representation of the
RFC 8070 freshness token, the MS-PKCA PAChecksum2 extension, the legacy
draft-19 request format, or a choice of CMS signing digest other than SHA-1. If
you cannot offer, omit, reorder, or rewrite an element, you cannot test whether
manipulating it downgrades anything.

We closed that gap with a small package that adds the missing ASN.1, monkeypatches
an installed minikerberos so its builder can populate the new fields, and reads
the agility indicators back out of the KDC's reply and error data. On top of it
sits one client per experiment, each of which changes exactly one thing.

## The property under test

Kerberos binds the request body into the pre-authentication data so that the
body the client signed is the body the KDC acts on. In PKINIT the client signs an
AuthPack with its certificate, and the PKAuthenticator inside it carries a
`paChecksum`: a SHA-1 hash over the KDC-REQ-BODY. That checksum is what stops an
attacker from tampering with the unsigned request body while keeping a valid
signature. Everything we tested is, in one way or another, about whether that
binding and the algorithms around it can be weakened.

MS-PKCA extends the RFC 4556 PKAuthenticator with two later fields: the RFC 8070
`freshnessToken` at tag [4], and its own `PAChecksum2` at tag [5], which carries
a checksum plus an algorithm identifier so the request-body binding can move off
SHA-1. Server 2022, 23H2, and later DCs advertise the CMS digests they accept in
a `TD-CMS-DIGEST-ALGORITHMS` typed-data element, per RFC 8636.

## Lab and method

The lab is an isolated `reflect.lab` domain on VMware: a Server 2025 DC
(`DC01`, 10.10.20.10), a Server 2025 CA host (`SRV01`, 10.10.20.11) running AD CS
with a Kerberos Authentication template, and Kali (10.10.20.50) as the client. A
test principal `pkitest` holds a certipy-enrolled logon certificate. We read the
KDC's response two ways for every test: the KRB-ERROR or AS-REP on the wire, and
the correlated Security-log event on the DC (4768 for a successful TGT, 4771 for
a pre-authentication failure), queried locally with `Get-WinEvent`.

Two rules kept the results honest. First, one deviation per test: everything else
stays conformant, so any change in the outcome is attributable to that one
element. Second, an integrity gate on every client. Before we trust a reply, the
client re-decodes its own request out of the signed CMS and confirms the intended
manipulation is actually on the wire. This is not optional caution. Early on, an
encoder quietly dropped a field we thought we were sending, which would have read
as a KDC behavior rather than the tooling bug it was. The gate turns a silent
setup artifact into a loud, visible failure.

## Findings

### KDF negotiation is inert on this path (C5)

RFC 8636 lets the client advertise a `supportedKDFs` list and the KDC echo the
selected `kdf` in its reply. The designers made the KDF path fail closed: the
reply key is derived from the whole request, so a naive downgrade produces a
decryption failure rather than a silent success.

We advertised four different offers: SHA-1 only, the full SHA-256/384/512/1 set,
SHA-256 only, and no offer at all. Every case produced the same result. The KDC
issued a TGT, the reply carried no `kdf` field, and minikerberos' legacy RFC 4556
key derivation decrypted it successfully, including the SHA-256-only offer where
we advertised no legacy KDF. A conformant agility implementation would either key
off SHA-256 (making the legacy decryption fail) or reject the offer it could not
satisfy. It did neither.

The conclusion is that Server 2025's domain certificate-AS path does not engage
the RFC 8636 reply-KDF machinery. It ignores `supportedKDFs` and keys off the
RFC 4556 default regardless. The no-offer baseline is identical to the offered
cases, which rules out any reading where our field confused the KDC. There is no
KDF agility to downgrade here.

### The request-body checksum is mandatory (C1)

We removed the `paChecksum` from the PKAuthenticator and changed nothing else.
The KDC rejected the request with error 79, `KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED`,
recorded on the DC as event 4771 with failure code 0x4F. A control run with the
checksum present issued a TGT. The only variable is the checksum, so this is a
clean fail-closed: the request-body binding is enforced, and the interop
regression that first surfaced this error on Server 2025 is deliberate
tightening rather than an accident.

### The legacy request format is not processed (C4)

Windows 2000 shipped a pre-RFC PKINIT request format, still assigned padata type
14, whose PKAuthenticator carries no checksum at all. If Server 2025 still
accepted it, the checksum requirement we just confirmed could be sidestepped by
using the older format. We built the draft-19 AuthPack and sent it as padata 14.

The KDC returned error 25, `KDC_ERR_PREAUTH_REQUIRED`, and logged no Security
event at all. That is the signature of an unrecognized pre-authentication type:
the KDC discards it and asks the client to authenticate, rather than processing
and failing it (which would produce a 4771). To remove any doubt that our
draft-19 structure was simply malformed, we ran a control that sent a known-good,
TGT-issuing NEW-format AuthPack under padata type 14. It produced the same error
25 with no event. Since the inner content was byte-identical to a request that
works under type 16, the padata number alone is what the KDC rejects,
independent of content.

The KDC's PREAUTH_REQUIRED data advertised the pre-authentication it does accept:
`PK_AS_REQ` (16, the modern request) but not `PK_AS_REQ_19` (14). It still
advertises the OLD reply identifier (15) for backward compatibility, so
request-side legacy support is gone while reply-side compatibility remains. That
same data also advertised `TD_CMS_DIGEST_ALGORITHMS` (111), which pointed us at
the next experiment.

### The CMS signing digest is coupled to the checksum requirement (documented)

The 111 element is where the KDC publishes the CMS signing digests it accepts.
This is the agility surface that was dead for KDF but is clearly active for CMS
digests, so we tested it directly: sign the request with each of SHA-1, SHA-256,
SHA-384, and SHA-512, and compare what the KDC accepts against what it advertises.

The KDC advertised all four digests. It accepted SHA-1 and issued a TGT. It
rejected all three strong digests with error 79, the same checksum error from
C1, even though every request carried a correct SHA-1 `paChecksum`. We confirmed
this was a genuine policy decision and not a signature-encoding artifact by
re-running with the combined `<hash>WithRSAEncryption` signature OIDs instead of
generic `rsaEncryption`; the result was identical, and the DC logged each strong
digest rejection as a 4771 with failure code 0x4F. A signature the KDC could not
verify would have produced `KDC_ERR_INVALID_SIG`, not a checksum error, so the
KDC verified the signature and parsed the AuthPack before deciding the SHA-1
checksum was insufficient.

The mechanism is that a strong CMS digest makes the KDC require the stronger
`PAChecksum2` instead of accepting the legacy SHA-1 `paChecksum`. We confirmed
this end to end. Adding a `PAChecksum2` with a SHA-256 algorithm at tag [5]
cleared error 79 and issued a TGT; removing it reproduced the error. This also
confirmed the tag placement, which follows the freshness token per MS-PKCA 2.2.3.

This behavior is documented. MS-PKCA Appendix A note 11 lists the conditions
under which PAChecksum2 is validated, and one of them is a non-SHA-1 signing
digest together with EC not being allowed. So the coupling we characterized is
intended, and the PAChecksum2 extension is a Server 2022 and later feature. We
confirmed and instrumented it; we did not discover it.

### PAChecksum2 validation is sound (C2, C3)

Documentation tells you when PAChecksum2 is validated, not how soundly. We tested
that directly. With every request signed SHA-256 (so PAChecksum2 was required)
and carrying a correct SHA-1 `paChecksum`, we varied only the PAChecksum2 value.

A present-but-forged checksum was rejected. A checksum computed over a different
request body was rejected. A checksum whose length and value did not match its
declared algorithm was rejected. All three produced error 41,
`KRB_AP_ERR_MODIFIED`, logged as a 4771 with failure code 0x29. The KDC verifies
the checksum against the request body; it does not merely check that the field is
present. The only manipulation accepted was a PAChecksum2 whose algorithm was
SHA-1 with a correct SHA-1 checksum, and MS-PKCA states that a present PAChecksum2
is validated even when it is SHA-1, so that is documented behavior. There is no
validation bypass.

### RSA reply mode is refused (C6)

RFC 4556 offers a second reply-key mode where the KDC encrypts the reply key to
the certificate's public key instead of using Diffie-Hellman. The client selects
it by omitting `clientPublicValue`. In that mode only the SHA-1 checksum binds
the exchange, which would be the softer target. Server 2025 refused it with error
60, `KRB_ERR_GENERIC`, matching MS-PKCA Appendix A note 20, which states the mode
is not supported. The softer target is simply not reachable.

## Detection telemetry

The failure modes are distinguishable on the defender's side, with one blind
spot worth knowing.

| Failure mode | KRB-ERROR | Event 4771 failure code |
|---|---|---|
| checksum absent, or present but insufficient strength | 79 | 0x4F |
| checksum present but invalid (forged, tampered, inconsistent) | 41 | 0x29 |
| legacy OLD-format request (padata 14) | 25 | no event |

An invalid checksum (0x29) is distinguishable from an absent or insufficient one
(0x4F). What is not distinguishable within 0x4F is a wholly missing checksum from
a present-but-insufficient-strength one; both look identical to a defender. And a
legacy OLD-format PKINIT attempt leaves no Security-log record at all, since the
KDC discards the padata without treating it as an authentication attempt. That
last point is the one detection gap here: a request type the KDC does not process
also does not audit.

## Verdict and prior-art boundary

Server 2025's PKINIT algorithm-agility surface held on every axis we tested. The
request-body binding is mandatory and correctly verified, the legacy format is
gone, KDF agility is inert rather than downgradeable, the RSA reply mode is
refused, and the one behavioral coupling worth a mention, a strong CMS digest
requiring PAChecksum2, is documented in MS-PKCA. We found no novel vulnerability.

We think that is a useful result to publish. A negative from a rigorous test tells
the community this surface is sound, which nobody had verified offensively, and
the method generalizes to the next protocol that ships agility. The reusable
output is two things: the tooling, so the next person can reproduce the moment a
real bug does appear, and the KRB-ERROR-to-event map above, which is the kind of
detection data that is rarely written down.

## Tooling

[pkinit-agility](https://github.com/cbev0x/pkinit-agility) contains the extended
ASN.1, the minikerberos monkeypatch, the reply and error reader, one client per
experiment, and a Kerberos MITM proxy with a CMS-digest downgrade forge. The
extended structures are a clean, standards-tracking addition and are candidates
for upstream contributions to minikerberos and PKINITtools. It is research tooling
for isolated labs and authorized testing only.

## References

RFC 4556 (PKINIT), RFC 8636 (algorithm agility), RFC 8070 (freshness), MS-PKCA
(Windows PKCA, sections 2.2.3 and Appendix A). Built on minikerberos by skelsec
and PKINITtools by Dirk-jan Mollema and Tamas Jos.
