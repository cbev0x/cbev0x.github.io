---
title: "The Authenticator Nobody Reads: Characterizing Non-PAC Kerberos AuthorizationData (ad-types 141-144)"
date: 2026-08-18
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Authorization, Research]
published: true
---

Everyone who studies Kerberos authorization studies the PAC. It is where the group memberships live, it is what the KDC signs, and it is what a decade of delegation and forgery research has centered on. But the PAC is not the only authorization data a Windows client puts on the wire. Inside the AP-REQ authenticator, sealed under the session key so a packet capture never shows it, sit a handful of quieter elements: ad-types 141 through 144. They carry the token restriction that decides whether a logon is filtered, the loopback marker, the channel-binding flags, and a client-asserted statement of who the ticket was meant for.

I spent a while pulling each of these apart in an isolated lab, forging them, and firing the results at live Windows and Samba acceptors to see what actually gets checked. This post is the whole map. None of it is a zero-day, and I want to be clear about that up front. What it is instead is a precise account of what each element does, what a server enforces, and where the three major Kerberos stacks diverge. Some of that has never been written down, and a couple of the pieces are directly relevant to how relay defenses hold up.

## The elements

Four authorization-data types travel in the authenticator, all wrapped in an AD-IF-RELEVANT container so that a server which does not understand one is required to ignore it.

Ad-type 141 is `KERB_AUTH_DATA_TOKEN_RESTRICTIONS`. It carries an `LSAP_TOKEN_INFO_INTEGRITY` structure: a flags field distinguishing a full token from a UAC-filtered one, an integrity level, and a 32-byte MachineID. On Windows Server 2025 it also carries a second 32-byte field, the CrossBootMachineID, which I will come back to because it is new and undocumented.

Ad-type 142 is `KERB-LOCAL`, the loopback marker. Ad-type 143 is `AD-AUTH-DATA-AP-OPTIONS`, a four-byte little-endian flags value carrying the channel-binding bit (`KERB_AP_OPTIONS_CBT`, 0x4000) and an unverified-target-name bit (0x8000). Ad-type 144 is `KERB_AUTH_DATA_CLIENT_TARGET`, the client's own statement of which service principal name it believed it was authenticating to.

All four live only in the authenticator, never in the service ticket, and the authenticator is encrypted. To read them I decrypt the ticket with the service account key to recover the session key, then decrypt the authenticator with that. To forge them I hook the one DER encoder every impacket AP-REQ path funnels through, and splice chosen authorization-data into the authenticator on its way to bytes.

## What is already known

This is not virgin ground, it is shallowly explored ground. James Forshaw mapped the consumption side of 141 on Windows in 2022: LSASS calls `LsaISetSupplementalTokenInfo`, treats a MachineID equal to the local machine's as a loopback, and clamps the integrity level down rather than ever raising it. The reflection and relay macro-area around 144 is a crater, with Forshaw's 2021 marshalled-target work, the 2025 Reflective Kerberos Relay (CVE-2025-33073), and the Ghost-SPN bypass (CVE-2025-58726) all landing there. MS-KILE specifies that a client emits these elements and that a server must check the MachineID and ignore 141 and 142 on mismatch.

What none of that covers is the acceptor-side handling of the 144 element itself. Whether a server enforces the client's asserted target, how it enforces it, and whether Samba or MIT do anything with these elements at all: those were open. That is the gap this fills.

## 141: the loopback gate is transport-bound

The interesting question for 141 is whether you can forge the restriction entry to lift a token filter. The one principal in my lab that matters here is a non-RID-500 domain local-admin whose network logons come back filtered, Elevated=No. If a forged 141 could flip that to a full token, that would be a real local privilege gain.

It cannot, and the way it fails is instructive. I ran three probes as that filtered principal. A 40-byte restriction with a MachineID matching the target completed but stayed filtered. A 72-byte restriction with a matching MachineID and a random CrossBootMachineID also stayed filtered. But a 72-byte restriction where both the MachineID and the CrossBootMachineID matched the target's real values did not just get ignored, it got the AP-REQ rejected outright: a KRB-ERROR, `KRB_AP_ERR_MODIFIED`, reproduced every time.

So the loopback restriction is not something you can assemble in an authenticator from off the box. Matching the MachineID alone changes nothing. Matching both per-machine identifiers is actively policed and treated as tampering. The gate is transport-bound, and forging it harder makes it fail closed, not open.

The CrossBootMachineID is worth dwelling on because I have not seen it documented anywhere. It is a second 32-byte identifier that Windows Server 2025 added to the LSAP structure, taking it from 40 to 72 bytes. I recovered its live value off the wire, confirmed its position in the structure, and confirmed that it participates in the anti-forgery check above. If you are parsing WS2025 authenticators, that is the field you are missing.

## 144: an enforced target binding

Ad-type 144 is where the useful findings are. It is the client saying "I believe I am talking to cifs/srv02." The question is what the server does with that.

First I had to fix my own encoding. I had assumed the target rode as an ASN.1 GeneralString. It does not. Pulled off a real WS2025 capture, the 144 value is a bare UTF-16LE string with no wrapper at all, for example 66 bytes for `cifs/DC01.reflect.lab@REFLECT.LAB`. Once I matched that byte-for-byte I could forge a 144 the acceptor would parse.

Then the enforcement test, firing at a live Windows SMB service with the session ticket held constant and only the 144 varying. With 144 matching the ticket, the login proceeds. With 144 stripped entirely, the login also proceeds, so its absence is tolerated. But with 144 asserting a different target than the ticket was issued for, the server rejects the AP-REQ with `KRB_ERR_GENERIC`. That is a different error than the 141 gate's tampering rejection, and it is a different code path: a semantic wrong-target refusal.

So 144 is a real anti-relay tripwire. A relayed AP-REQ that carries the victim's original 144 gets caught the moment it lands on a service whose identity does not match that assertion. The known relay attacks slip past this only because they are same-host reflections that keep the name consistent. Any cross-service relay that carries a 144 trips it.

### It holds across name forms

I wondered whether an IP-form target would be treated as unverifiable and skipped. It is not. When I force a client onto Kerberos-to-IP, it stamps the IP literal into 144 verbatim, `cifs/10.10.20.12@REFLECT.LAB`, with no reverse resolution to the canonical host. And the acceptor enforces it exactly as it enforces a hostname: a mismatched IP-form 144 is rejected with the same `KRB_ERR_GENERIC`. Windows string-compares the assertion against the service identity and refuses on mismatch whether the form is a hostname or an IP literal. The tripwire covers IP-based coercion, not only DNS-name relays.

### It binds the exact SPN, including service class

Next question: does 144 bind the whole SPN, or just the hostname? The target account holds both `cifs/srv02` and `HOST/srv02`, so I could present a ticket for one class and assert the other in 144, same host, both real SPNs on the account. Both directions reject with `KRB_ERR_GENERIC`. Ticket `cifs/srv02` with 144 asserting `HOST/srv02` is refused, and the reverse is refused too.

So the comparison is symmetric and exact. It is not hostname-scoped and it is not account-scoped, it is ticket-SName-exact: the 144 assertion must equal the SName of the ticket it rides with, string for string, service class included. `cifs/` and `HOST/` are distinct identities to the acceptor even on the same account and the same host. That is the tightest form the check could take, and it means even a same-host cross-service-class relay is caught.

### The one thing it does not catch

Here is the finding with teeth. 144's check is keyed on the ticket's own SName, which means it accepts any SName the target account actually holds, and it does not care whether that name is legitimate. I registered a ghost SPN on the target account, `cifs/ghost01.reflect.lab`, a name that has no business pointing at that server. With a ticket minted for the ghost and 144 asserting the same ghost, the acceptor accepts. With 144 asserting a ghost the account does not hold, it rejects. Same result for a `HOST/`-class ghost.

So 144 does not distinguish a ghost SPN from a real one. And that matters because the ghost SPN is exactly the precondition for the Ghost-SPN relay (CVE-2025-58726). The same ghost that enables that attack also satisfies 144. In other words, 144 adds no barrier beyond what the attacker already needed. On a patched host, SMB signing remains the sole control on that path. This is not a weakness in 144's logic, it is a statement of its scope: a defensive check that fires on target mismatch simply does not constrain an attack whose whole setup is to make the names match.

I want to be careful about the claim. This is the acceptor-side check shown to be ticket-SName-keyed, verified on the wire with paired accept and reject cases. It is not a demonstrated live relay on a patched box. Signing was held constant and I did not drive the marshalled-target client path end to end, for a reason I will get to.

### The flag that could have relaxed it, and does not

The 143 options field has a bit, 0x8000, `UNVERIFIED_TARGET_NAME`, that means the client could not verify the target name it is asserting. That is the one mechanism in this whole surface that pointed toward weakening enforcement rather than strengthening it. If the acceptor read that bit as permission to skip the 144 check, then setting it in a forged authenticator would wave a mismatched 144 straight through, which would be a genuine client-settable relay primitive.

It does not. I fired the known-reject case, a mismatched 144, twice: once with 143 carrying CBT only, once with CBT plus the unverified bit. Both reject identically with `KRB_ERR_GENERIC`, and the probe confirmed the flag was actually set on the wire. Windows does not trust the client's own "I could not verify this" flag as license to skip the target binding. The bit is advisory at most. That is the correct design, and it closes the last place on this surface where forgery could have bought anything.

## The marshalled-target path, and why I did not fake it

The obvious next move for 144 is the marshalled-target trick from the reflection attacks. I deliberately did not test it, and the reason is worth stating because it would have been easy to produce a misleading result.

The marshalling trick is a client-side DNS mechanism. The attacker plants a hostname like `<victim>1UWhRC...` where the suffix is a marshalled `CredMarshalTargetInfo` blob. The SMB client resolves that hostname and `SspiExProcessSecurityContext` strips the marshalled portion before Kerberos ever builds the SPN. So in the real flow no marshalled SPN is ever registered and no ticket is ever issued to the marshalled name. The name exists only client-side, before the strip, and the resulting ticket is for the victim's real SPN.

That means the tempting lab shortcut, registering the marshalled string as an SPN and minting a ticket to it, does not model the attack at all. It is just the ghost test with a longer name, and it would produce an accept that looks like a marshalled-target result but is not one. The honest version of the question is entirely client-side: does a patched client, driven at a marshalled DNS record, emit a 144, and naming what. On patched builds the client-side fix blocks the marshalled name upstream, so the honest predicted answer is that the client emits nothing. Reaching a real verdict needs a patched-client capture harness, not a forging tool that stands in the wrong place in the pipeline. I would rather leave the cell open and labeled than fill it with a result that does not mean what it appears to.

## The cross-stack picture

Windows is not the only implementation, and this is where a clean differential falls out. I tested what each of the three major stacks does with these elements, both as an emitter and, for 144, as an acceptor.

On the acceptor side, Samba does not enforce 144. Firing the same mismatched-target AP-REQ at a real `smbd`, the mismatch that Windows refuses with `KRB_ERR_GENERIC` is accepted, confirmed on the wire. Reading the embedded Heimdal source shows why, and it is structural rather than a bug. Heimdal's `build_auth.c` emits the client-target as it builds an AP-REQ, so Heimdal-as-client does produce a 144, and its encoding is byte-identical to the Windows one, which independently confirms my wire analysis. But the acceptor side only ever fetches the etype-negotiation and channel-binding elements. The target-principal element appears exactly once in the whole tree, at the emit site. There is no consumer, no comparison, anywhere. Heimdal emits 144 and never checks it.

That is spec-compliant. Ignoring an unimplemented AD-IF-RELEVANT extension is exactly what the container is for. It is a defense-in-depth gap, not a violation, and it is not reachable as a live relay on a default Samba DC anyway because SMB signing and LDAP strong-auth sit in front of the acceptor. But the asymmetry is real and worth naming: the client-target binding is half-implemented in Heimdal, emitted but never verified, where Windows both emits and enforces.

The emission side gives a three-way split. Capturing and decoding a real AP-REQ authenticator from each stack: Windows emits all four of 141, 142, 143, 144. Heimdal emits 143 and 144 plus ad-type 129, the etype-negotiation element, but never the 141 restriction or the 142 loopback marker. MIT emits nothing at all. I confirmed the MIT result twice, once with a default GSS context and once with the full mutual-auth, confidentiality and integrity flag set that a real SMB client requests, and the authenticator carried no authorization-data either time.

So the richness runs Windows, then Heimdal, then MIT-empty. The entire 141-through-144 surface is a Windows-native construct. Heimdal mirrors part of it, the channel-binding and client-target and negotiation elements, but not the restriction and loopback pair that are the most Windows-specific. MIT's GSS initiator does not participate at all. If you are reasoning about what a non-Windows client puts in its authenticator, that is the shape of it.

## 142 in brief

I characterized the loopback marker structurally without fully closing it. The 16-byte value decodes as two little-endian quadwords: a value in the x64 user-mode heap range, which reads as a pointer into the emitting LSASS, and a smaller integer that looks like a counter or id. It is constant across every AP-REQ of a single authentication. Whether it is stable across separate authentications or across a reboot I could not pin down, because it needs a real Windows client capture my lab's virtual switching would not produce. But the security-relevant conclusion does not depend on that: a value that is meaningful only inside the emitting LSASS address space is definitionally unverifiable by any other machine, which is the same loopback-only logic that governs 141. It is an opaque local handle, and you cannot forge it to match without the victim's live heap layout.

## What this adds up to

There is no forgeable primitive anywhere in 141 through 144 that buys a privilege gain or a relay bypass on a patched Windows host. Every element is defensive by construction. The 141 restriction rejects a both-identifier match as tampering. The 144 binding is exact and rejects mismatches, and the one flag that could relax it does not. The 142 marker is an unforgeable local handle. Forging these mostly makes an attacker more restricted, not less, and in the two places where forgery could plausibly have helped, the implementation specifically blocks it.

What is worth taking away is the map. The CrossBootMachineID is a real new WS2025 field with a role in an anti-forgery check, now documented. The 144 element is an enforced, ticket-SName-exact anti-relay tripwire that holds across hostname and IP forms, which is a defensive property worth knowing about when reasoning about coercion and relay. Its one blind spot, ghost SPNs, is exactly the Ghost-SPN precondition, so it adds no barrier there. And the cross-stack differential is clean: Windows enforces and emits the full set, Heimdal emits most of it but enforces none of the target binding, and MIT sits it out entirely.

I went looking for an attack and found a defense, characterized end to end. That is a fine result. The elements nobody reads turn out to be doing quiet, mostly-correct work, and now there is a written account of exactly what that work is.
