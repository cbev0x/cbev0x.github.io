---
title: "Cross-Forest DAC Claims: What AllowAll Actually Allows"
date: 2026-08-04
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Claims, DAC, Silos, Research]
published: true
---

## The question

Cross-forest trust security is usually discussed in terms of SID filtering. The parallel path, claims transformation, decides which claims cross a forest boundary. Since claims can gate authorization through Dynamic Access Control, I wanted to know whether the claims-transformation path has the same containment as SID filtering, and where it does not.

I built a two-forest lab, both claims-enabled, and instrumented the tickets at each hop.

## The default is fail-closed

The good news first. With no ingress claims-transformation policy configured, the trusting forest drops every inbound claim. `msDS-IngressClaimsTransformationPolicy` absent means all ingress claims are dropped by pure default. A low-privilege user in forest B, authenticating across the trust, arrives at forest A carrying nothing. The "insecure default" version of this does not exist.

There is a second, separate reason accidental leakage cannot happen. A claim type's identifier carries a forest-scoped component in its hash. Forest B's naturally defined UserCity claim and forest A's UserCity claim resolve to different IDs even though they share a name and a source attribute. So two forests independently defining the same claim will never accidentally alias. An accidental cross-forest collision is impossible.

## The footgun: AllowAll plus a forced ID

Now flip the trusting forest to an AllowAll ingress policy, which is a real option an admin can set. Two facts combine badly.

First, cross-forest claim acceptance under AllowAll is keyed on the claim's type ID, and there is no origin validation. Forest A surfaces exactly those inbound claims whose type ID matches a locally defined claim type, and it treats them as its own native claims.

Second, while forest-scoped hashing blocks accidental collisions, an adversarial or compromised trusted forest can deliberately forge the ID. I created a claim type in forest B and forced its identifier to match forest A's local UserCity ID. A user in forest B authenticating across the trust then arrives at forest A carrying a claim that forest A reads as its own native UserCity.

I confirmed it end to end. A forest B user with the forced-ID claim set to a target value crossed the trust, and a file share in forest A whose conditional ACE gated on the local UserCity claim granted access. Under AllowAll, the trusted forest did not just assert claims in a partner namespace; it impersonated forest A's own local claim namespace.

## The airtight on/off

The whole thing toggles cleanly, which is what makes it a defensible characterization rather than an anecdote. Same user, same forged claim, same share: under AllowAll the service ticket carries the claim and access is granted; reverted to the drop-all default, the ticket's claims buffer comes back zero-length and access is denied. AllowAll grants, drop-all denies, nothing else changed.

## The negatives are as important as the positive

I pushed on the correctly configured filters and they held. `DenyAllExcept` resolves the allowed claim to a local type and filters by ID, so a blocked claim cannot slip in by sharing a name. The transformation rule language is type-only: it matches on claim type with exact `==` or a `*` wildcard, there is no value-based filtering to abuse, and `DenyAll` via a `!~ "*"` rule is airtight, including against claim types whose IDs contain colons and slashes. There is also a second filter behind the transform: even under AllowAll, the KDC drops any claim whose ID is not a locally defined type. The forced-ID trick works precisely because it clears that second filter by matching a local type.

So the only real exposure on this surface is the AllowAll footgun: it requires an admin to choose AllowAll over the recommended `DenyAllExcept`, and it requires an adversarial or compromised trusted forest. That is a by-design, admin-responsibility posture, not a serviceable vulnerability. It is worth writing up because the sharp edge, that AllowAll lets a partner forge your local claim namespace with no origin check, is not obvious from the setting's name.

## describeClaims, because the parsers are blind

I could not have measured any of this with existing tooling. impacket's `describeTicket` drops PAC buffers 13, 14, and 15 as unsupported, and impacket's PAC layer wraps the client-claims buffer as a raw blob with no `CLAIMS_SET` decoder. Both are blind to claims. That blindness sent me down a long false lead before a positive control flushed it, chasing cache and reboot theories when the real issue was that my tool simply was not reading the buffer.

So I wrote `describeClaims.py`: it decrypts the ticket, walks the PAC, and decodes the `CLIENT_CLAIMS_INFO` buffer, reading string claims by ID and value. It is a research microscope, not a polished release, but it is the reason the AllowAll result and every negative above are measured rather than assumed.

The proper fix belongs upstream. impacket genuinely lacks a claims decoder: a real contribution is a full NDR `CLAIMS_SET_METADATA` to `SET` to `ARRAY` to `ENTRY` walk, all four value types, XPRESS-Huffman decompression for the compressed blobs, and wiring it into `describeTicket` and the PAC module. That is on my list as a pull request. Until it lands, the lesson stands: do not trust `describeTicket` for claims presence, because absence in its output is a tool artifact, not a fact about the ticket.
