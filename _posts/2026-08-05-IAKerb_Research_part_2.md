---
title: "IAKerb on MIT and Samba: A Pre-Windows Attack-Surface Baseline"
date: 2026-08-05
categories: [Personal, Research]
tags: [Windows, Active Directory, NTLM, Kerberos, Samba, MIT-krb5, Research]
published: true
---

## Why baseline before Windows

NTLM is on its way out, and IAKerb and LocalKDC are the two Kerberos features Microsoft is shipping to remove the fallback. IAKerb lets a client authenticate with Kerberos even when it cannot reach a domain controller, by relaying its KDC messages through the server it is talking to. LocalKDC gives local accounts a Kerberos path by running a tiny KDC inside LSA. Both are targeted for general availability in the second half of 2026.

I did not wait for that. IAKerb is an IETF mechanism, and the reference implementations carry it today, so its wire behavior, its integrity properties, and how it looks to a KDC are all testable now on MIT krb5 and Samba. The point of doing it early is the diff. When a Windows build carrying IAKerb is testable, I re-run each of these tests and see where Windows agrees with the reference stack and where it does not. This post is IAKerb only. LocalKDC has no non-Windows analog, so it waits for the build.

Everything below is a reference-implementation baseline, not a claim about Windows. The value is in having the baseline drawn before the mechanism is everywhere.

## The rig

The setup is three roles on three stacks. An MIT krb5 1.22.1 client is the initiator. An MIT acceptor relays for it. A Samba 4.24.0 AD DC is the KDC. For the cross-stack question I add a second acceptor built against Heimdal 1.20.x on Debian 12.

I drive the exchange with a small python-gssapi harness that requests the IAKERB mechanism explicitly by its OID, `1.3.6.1.5.2.5`. That explicit request matters, and I come back to why. The harness runs initiator and acceptor as separate networked processes so the tokens actually cross a socket, and a second tool, a TCP interposer, sits in that token stream as a stand-in for a rogue relay: it forwards every framed token in both directions and can corrupt a chosen byte on the way through. For observation I lean on `KRB5_TRACE`, `tshark` against the KDC, and Samba's JSON authentication audit.

One piece of discipline runs through every test. IAKerb is skipped if the initiator already holds a matching ticket, so each run starts from an empty credential cache. Skip that and you watch plain Kerberos happen and conclude nothing, which is exactly the trap that made a Windows client fall to NTLM in my earlier IAKerb testing.

## The KDC never learns about IAKerb

The first thing to establish is that the relay works and the KDC is unaware of it, because that fact frames everything else.

Requesting IAKerb from an empty cache, the exchange walks the full mechanism. The initiator wraps its AS request in an IAKERB proxy token, the acceptor unwraps it and sends an ordinary AS request to the KDC, and the reply comes back the same way. Then the same pattern for the TGS exchange, and finally a normal AP exchange between the initiator and the acceptor. On the wire to the Samba DC I see exactly what a direct client would produce: an AS exchange that falls back from UDP to TCP to carry the PAC-bearing reply, and a TGS exchange, both for `iaktest` against `host/app.samba.lab`, all in realm `SAMBA.LAB`. Nothing in those requests says IAKerb. The KDC issues tickets as it always would.

![](/assets/img/2026-08-05-IAKerb_Research/iakerb_relay_flow.png)

The token structure is legible in the headers. The AS and TGS legs are IAKERB proxy messages carrying token-id `0x0501`. The final AP request is token-id `0x0100`, and its reply `0x0200`, all still under the IAKERB OID. A useful side observation for triggering: when the initiator already holds the service ticket, the envelope stays IAKerb but the token-id jumps straight to `0x0100` and the proxy legs are skipped entirely. The skip is a one-byte difference, `0x0501` versus `0x0100`, and it is the same reason IAKerb quietly does nothing when a ticket is cached.

The load-bearing conclusion is simple. The KDC is stack-neutral. It services a relayed request as ordinary Kerberos, so Samba sits on the KDC side of the line and IAKerb itself is entirely an initiator-and-acceptor concern. That is why the rest of this post is about what the relay can and cannot do, and what the KDC can and cannot see.

## The conversation is bound, and I can watch the binding catch a relay

IAKerb relays authentication messages through a third party, so the obvious question is whether that third party can tamper with them. The specification binds the conversation with a finished checksum carried in the final AP authenticator, computed over the IAKerb exchange. I wanted to see that binding actually reject a man in the middle, so I put the interposer between initiator and acceptor and corrupted one byte at a time at different points, mapping where each corruption is caught.

It is not one check, it is a stack of them.

| Byte I corrupted | What caught it | Signature |
|---|---|---|
| realm in the IAKerb header, request | the relay's own KDC lookup | "IAKERB proxy could not find a KDC" |
| inner AS-REQ body, request | the KDC | "KDC did not respond to the IAKERB proxy" |
| AP-REQ outer framing, request | nothing | context completed |
| realm in the IAKerb header, response | the finished binding | AP step fails, bad-integrity |

![](/assets/img/2026-08-05-IAKerb_Research/iakerb_integrity_tier_map.png)

The top two tiers are unsurprising. Corrupt the realm in the request header and the relay cannot find a KDC for the garbage realm, so it fails before any KDC contact. Corrupt the inner AS request and the KDC rejects the mangled message. The third row is a genuine data point: a byte in the AP request's outer framing was tolerated and the context completed, so not every byte is integrity-covered.

The fourth row is the one I was after. I corrupted a byte in the acceptor's response that the initiator receives, in the outer header rather than the inner reply, so the initiator still decrypted its ticket and finished the AS and TGS legs normally. The context then died at the AP step with a decrypt integrity failure. The two ends had built their finished checksums over different views of the conversation, because the man in the middle altered one of them, and the AP step refused the mismatch.

What lets me attribute that specifically to the conversation binding, and not to generic AP integrity, is the contrast between the third and fourth rows. Tampering the AP request itself was tolerated. Tampering the conversation so the two sides disagreed was rejected. The failure is not "the AP request changed," it is "the two parties saw different exchanges," which is precisely the finished binding doing its job. So the picture is defense in depth: relay routing, KDC message integrity, AP encryption, and a finished checksum over the whole relayed conversation as the backstop.

## Can a rogue relay retarget you

![](/assets/img/2026-08-05-IAKerb_Research/iak3_relay_can_cannot.png)

This is the sharp question, because the relay sits in the middle of the client's ticket requests. The requested service name is in cleartext in the TGS request, so a rogue relay can plainly read which service you are asking for. Observation is trivial. The question is whether it can change it.

It cannot. I flipped a character in the requested service name two ways. First to a name that does not exist, and then to a second service principal I had registered on the same account beforehand so that the retarget destination was genuinely valid. Both attempts produced the identical rejection from the KDC, error-code 31, `KRB5KRB_AP_ERR_BAD_INTEGRITY`.

The mechanism is the reason the result is airtight. The service name sits in the cleartext request body, and that body is covered by a checksum inside the encrypted authenticator the client built. When the relay edits the name, the KDC decrypts the authenticator, recomputes the checksum over the modified body, and it does not match, so it rejects on integrity before it ever tries to resolve the name. The valid-SPN test is the control that proves this: if the block were merely "that name is unknown," the valid target would have behaved differently, and it did not. Same bad-integrity error either way.

So a rogue IAKerb relay can read the service you asked for but cannot silently steer you onto another one. The net effect of tampering is denial. The exchange fails, it does not redirect. And even the recovered path is closed, because after the KDC rejection the client's retry still ends at the finished binding described above. Two independent layers, one conclusion.

## Where the mechanism actually lives

Two smaller results settle who participates in IAKerb and how it is reached.

Heimdal does not participate. I pointed the MIT initiator at a Heimdal acceptor and ran a control first, plain krb5, which completed cleanly, proving the keytab, the socket, and Heimdal's GSS all worked. Then I flipped the same binary to IAKerb, and Heimdal rejected the token outright with major status `0x00010000`, an unsupported mechanism. Same acceptor, same credential, one variable changed, one outcome changed. Heimdal has no IAKerb acceptor, so Samba, which embeds Heimdal, does not participate in IAKerb at all. It is only ever the KDC behind the relay, which is consistent with the KDC-agnostic result above.

And on MIT, IAKerb is opt-in. Running the initiator under SPNEGO instead of an explicit request, the negotiation settled on krb5 and completed, and the IAKerb OID appeared zero times anywhere in the exchange. MIT never puts IAKerb in its SPNEGO mechanism list, so it is reachable only by a caller naming its OID directly.

Those two facts point the same way. IAKerb is an initiator-side concern of MIT and Windows, and on MIT there is nothing to downgrade, strip, or force through negotiation, because the mechanism is not on the table until someone asks for it. That is the contrast to keep in mind for Windows, where the client auto-invokes IAKerb the moment it decides it cannot reach a domain controller. On Windows the attack surface is that decision, the DC-locator state, not the mechanism list.

![](/assets/img/2026-08-05-IAKerb_Research/iakerb_cross_stack_boundary.png)

## What the KDC can and cannot see

The last question is detection, and it continues a thread from my earlier IP-SPN work, where I found the KDC blind to certain request origins at event 4769.

I turned on Samba's JSON authentication audit and generated one direct authentication and one relayed one, then compared the records. They are the same. A relayed AS and a direct AS both log as a `Kerberos KDC` authentication with the same account and the same authentication type. The service ticket logs as a `KDC Authorization` event, which is Samba's analog of 4769, again identical between direct and relayed. What matters is what is absent. There is no field that marks a request as relayed, and no field for a true originating client distinct from the sender. The only source information is `remoteAddress`, which is simply whoever opened the socket to the KDC.

So the KDC cannot distinguish a relayed request from a direct one, and it attributes the request to the connecting host. In a real deployment the connecting host is the relay, not the user. One honest caveat on my lab: the initiator and the relay shared an address, so this proves the schema-level blindness rather than showing a wrong address in the log. A split-host run would show the relayed record naming the relay while the account stays the user, which is the same story with a sharper picture. Either way, the origin-blindness I documented at 4769 carries straight onto the AS and TGS path under an IAKerb relay.

## What waits for Windows

Every result here is a reference-implementation baseline, and the value is the comparison still to come. When a Windows build carrying IAKerb is testable, the re-runs are already defined. Does the Windows client validate the returned service name where MIT relies on the request-body checksum. Does Windows enforce every integrity tier the reference stack does, or leave one looser. Does the Windows event log carry a relay marker that Samba's schema lacks. And how is the DC-locator auto-invoke forced, since that, not negotiation, is where the Windows action lives. LocalKDC is a separate baseline entirely, with no non-Windows analog, so its ticket format, its PAC, and its ephemeral signing key all wait for the build.

That is the head start. The mechanism's integrity and detection properties are characterized now, on stacks I fully control, so the Windows work becomes a diff against a known reference rather than a cold start on a moving preview.

## Reproducing this

The stacks are MIT krb5 1.22.1 as initiator and acceptor, Samba 4.24.0 as the KDC, and Heimdal 1.20.x on Debian 12 for the cross-stack acceptor. The method is two small tools: a python-gssapi harness that drives the IAKERB mechanism explicitly and runs initiator and acceptor over a socket, and a TCP interposer that relays the framed tokens and can corrupt a chosen byte to model a rogue relay. The one rule that makes any of it work is the trigger discipline, an empty credential cache and an explicit IAKerb request, or the mechanism quietly skips itself. Observation is `KRB5_TRACE` on both ends, `tshark` against the KDC, and Samba's `auth_json_audit` for the detection view.
