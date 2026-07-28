---
title: "What Samba 4.24 Actually Checks When It Re-Issues a PAC"
date: 2026-07-27
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, PAC, Research]
published: true
---

I spent a session pointing my PAC mutation tooling at a Samba 4.24 AD DC to find a
place where Samba and Windows disagree about PAC signatures. The thesis was simple. My
earlier work kept confirming Microsoft because it targeted a single mature validator, so
I went looking at a surface with the opposite property: a second implementation that has
to honor the same on-the-wire contract Windows defines. If Samba accepts a mutated PAC or
ticket that Windows rejects, that gap is an interop primitive.

I found no such gap. What I found instead is a clean, specific account of what Samba's KDC
verifies at three different points in a ticket's life, and I think the mechanism is worth
writing down even though the verdict is negative. A negative result with a mechanism tells
you where not to look next and why, which is more than most negatives give you.

## The setup

I decrypt a real, KDC-issued ticket with the relevant key, mutate one field or one
signature in its PAC, re-encrypt, and present it back. The delivery client matters more
than I expected. Impacket cannot drive Samba's KDC as a client: its TGS-REQ authenticator
carries a checksum type that Windows tolerates and Heimdal rejects outright, so every
request dies with KRB_AP_ERR_INAPP_CKSUM before the KDC ever looks at my PAC. Windows is a
liberal acceptor here and Samba is not, which is itself a small interop note. The fix is to
drive delivery with MIT userland, which speaks a checksum dialect Heimdal accepts. Every
result below runs through MIT `kvno`.

One control underpins all of it: an unmutated reseal has to be accepted before any mutated
reject means anything. I re-encode the decrypted enc-part with no change and confirm it is
byte-identical to what the KDC originally sealed. It is. So when a mutation is rejected, the
mutation is the only variable.

## Consumer one: the plain TGS request

The first question is whether Samba's KDC re-verifies the KDC signature (0x07) when it
copies a TGT's PAC into a service ticket. I changed PrimaryGroupId in a TGT, recomputed only
the server signature (0x06) with the krbtgt key, and left 0x07 stale.

Samba issued the service ticket and copied my change through. So on this path Samba does not
re-verify 0x07. That sounds like a gap until you look at the keying. On a TGT the ticket's
service is krbtgt, so both 0x06 and 0x07 are keyed by the krbtgt key. Verifying 0x06 already
proves the PAC came from a KDC, which makes 0x07 redundant on a TGT. I confirmed Samba does
verify 0x06 by corrupting it: that ticket is rejected with a decrypt-integrity failure. So
Samba checks one krbtgt-keyed signature and skips the other, which is minimal but sufficient.
Forging a valid 0x06 here needs the krbtgt key, and anyone with the krbtgt key already owns
the domain. No escalation lives on this path.

## Consumer two: S4U2Proxy evidence

This is the path with teeth, because it is where the two signatures are keyed differently. In
constrained delegation the KDC consumes an evidence ticket whose server signature is keyed by
the intermediate service's own key, which an attacker in that position holds, while the KDC
signature is keyed by krbtgt, which they do not. If the KDC does not re-verify 0x07 here, a
service-key holder can forge a more privileged evidence ticket. That exact forgery is
CVE-2022-37967, which Samba patched in 2022, so this is really a question of whether the fix
holds across the whole mutation space or leaves a seam.

I probed it three ways and got three distinct rejections, which together map the check
precisely. A byte-identical resealed evidence passes the integrity stage and fails only on an
unrelated forwardable policy check, so the reseal itself is clean. Any single altered byte in
the evidence, whether a ticket flag or PAC content, authenticated with only the service key,
is rejected with a decrypt-integrity failure. Samba binds the entire evidence enc-part end to
end. And deleting the KDC signature buffer entirely returns a named error, "PAC missing kdc
checksum," rather than a generic failure. That last one matters: it means the check is
require-present, not verify-if-present, so the classic missing-signature bypass does not exist
here. The fix holds across forge, alter, and strip. Nothing to disclose.

## Consumer three: the inbound cross-realm referral

The third surface is genuinely different. When a foreign user crosses a forest trust, the
referral TGT carries the *foreign* realm's krbtgt signature, which the receiving KDC cannot
verify because it does not hold that key. None of the end-to-end binding from the S4U2Proxy
path can apply, because the receiving KDC is not the signer.

I built a two-way trust between a Windows forest and samba.lab and watched a Windows user get
a Samba service ticket. The baseline read is the interesting part. Samba accepts the referral,
verifies only the inter-realm server signature it can check, copies the foreign identity
through verbatim without sanitizing the foreign domain SID, and re-stamps the issued ticket
with its own keys. I then forged PrimaryGroupId into the referral PAC, recomputed only the
inter-realm signature I could produce with the trust key, and left the foreign KDC signature
stale. Samba honored it.

This reads like forgery, and it is, but the calibration is the whole point. The capability is
gated on holding the inter-realm trust key, and that key is by definition the secret that lets
its holder forge cross-realm PACs. So "content signed with the inter-realm key is trusted" is
the expected behavior of the key, not a flaw, and it matches how Windows treats inbound
referrals. The one honest looseness I noted is that Samba does not sanitize the inbound foreign
domain SID where Windows applies inbound namespace filtering, but exploiting that still needs
the trust key, which places it in trust-abuse territory rather than an unprivileged
escalation.

## What this adds up to

Three consumers, three clean negatives, each with a mechanism:

- Plain TGS copies the TGT PAC through and verifies the server signature, which on a TGT is
  equivalent to proving KDC issuance. The KDC signature is redundant there and not separately
  checked.
- S4U2Proxy, where the server signature is no longer trustworthy, binds the whole evidence
  enc-part and requires the KDC signature to be present, closing the forgery the server
  signature alone would allow.
- The inbound cross-realm path trusts what the inter-realm key signs, cannot check the foreign
  KDC signature, and does not sanitize the foreign domain SID, all of which is gated behind a
  trust secret and consistent with Windows on the signature axis.

I did not find a Samba-accepts-what-Windows-rejects cell. What I have is a precise picture of
what Samba 4.24 checks at each re-issue point, which is the thing I actually wanted to know,
and a reusable harness for asking the same question of the next implementation. Sometimes the
useful output of a hunt is a clean map of where the walls are.
