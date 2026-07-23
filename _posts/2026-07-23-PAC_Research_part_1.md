---
title: "PACMutator: Fuzzing the PAC Validator Instead of Forging Tickets"
date: 2026-07-23
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, PAC, Research]
published: true
---

## What a PAC is, and why it is worth attacking

When a Kerberos ticket is issued in Active Directory, the domain controller staples a structure to it called the Privilege Attribute Certificate, or PAC. The PAC is where the user's authorization data lives: the user's RID, the groups they belong to, any extra SIDs, their UPN, and the timestamps of the logon. When a service later receives that ticket, it reads the PAC to decide who the caller is and what they are allowed to do. The PAC is, in effect, the KDC telling every service in the domain "here is who this person is, and I vouch for it."

That vouching is enforced by signatures. A PAC on a service ticket carries four checksums. The server signature is keyed with the service account's own key. The other three, the KDC signature, the ticket signature, and the extended-KDC signature, are keyed with krbtgt, the account whose key only the domain controllers hold. This split is the whole security model: a service can verify the server signature itself, but only a domain controller can verify the krbtgt-keyed ones, and only a domain controller can produce them. If any authorization field is altered, the krbtgt signatures no longer match, and a full validation catches it.

The diagram below is the structure I spent this project mutating. A service ticket's encrypted part holds the PAC, and the PAC is a small header followed by a table of buffers. Some buffers carry identity, and four carry signatures.

<svg width="100%" viewBox="0 0 680 470" role="img"><title>Anatomy of a PAC inside a Kerberos service ticket</title><desc>A service ticket's encrypted part contains authorization data holding the PAC, which is a table of seven buffers: identity buffers and four signatures.</desc>
<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
<g class="c-gray"><rect x="40" y="30" width="600" height="410" rx="20" stroke-width="0.5"/><text class="th" x="60" y="58">EncTicketPart (encrypted with the service key)</text></g>
<g class="c-blue"><rect x="64" y="78" width="552" height="344" rx="14" stroke-width="0.5"/><text class="th" x="84" y="104">PAC (PACTYPE header + buffer table)</text></g>
<g class="c-teal"><rect x="88" y="124" width="248" height="52" rx="8" stroke-width="0.5"/><text class="th" x="212" y="145" text-anchor="middle" dominant-baseline="central">LOGON_INFO</text><text class="ts" x="212" y="161" text-anchor="middle" dominant-baseline="central">User RID, groups, SIDs</text></g>
<g class="c-teal"><rect x="352" y="124" width="248" height="52" rx="8" stroke-width="0.5"/><text class="th" x="476" y="145" text-anchor="middle" dominant-baseline="central">UPN_DNS_INFO</text><text class="ts" x="476" y="161" text-anchor="middle" dominant-baseline="central">UPN, DNS, SID copy</text></g>
<g class="c-teal"><rect x="88" y="188" width="248" height="52" rx="8" stroke-width="0.5"/><text class="th" x="212" y="209" text-anchor="middle" dominant-baseline="central">CLIENT_INFO</text><text class="ts" x="212" y="225" text-anchor="middle" dominant-baseline="central">Name, auth time</text></g>
<g class="c-amber"><rect x="352" y="188" width="248" height="52" rx="8" stroke-width="0.5"/><text class="th" x="476" y="209" text-anchor="middle" dominant-baseline="central">SERVER_CHECKSUM</text><text class="ts" x="476" y="225" text-anchor="middle" dominant-baseline="central">Service key (forgeable)</text></g>
<g class="c-coral"><rect x="88" y="252" width="167" height="52" rx="8" stroke-width="0.5"/><text class="th" x="171" y="273" text-anchor="middle" dominant-baseline="central">KDC_CHECKSUM</text><text class="ts" x="171" y="289" text-anchor="middle" dominant-baseline="central">krbtgt</text></g>
<g class="c-coral"><rect x="271" y="252" width="167" height="52" rx="8" stroke-width="0.5"/><text class="th" x="354" y="273" text-anchor="middle" dominant-baseline="central">TICKET_CHECKSUM</text><text class="ts" x="354" y="289" text-anchor="middle" dominant-baseline="central">krbtgt</text></g>
<g class="c-coral"><rect x="454" y="252" width="146" height="52" rx="8" stroke-width="0.5"/><text class="th" x="527" y="270" text-anchor="middle" dominant-baseline="central">EXTENDED_KDC</text><text class="ts" x="527" y="288" text-anchor="middle" dominant-baseline="central">krbtgt</text></g>
<g class="c-amber"><rect x="88" y="330" width="512" height="74" rx="8" stroke-width="0.5"/><text class="th" x="344" y="352" text-anchor="middle" dominant-baseline="central">Server signature covers the whole PAC</text><text class="ts" x="344" y="372" text-anchor="middle" dominant-baseline="central">with the two checksum fields zeroed</text><text class="ts" x="344" y="390" text-anchor="middle" dominant-baseline="central">krbtgt signatures chain on top of it</text></g>
</svg>

## Why the existing tools do not help here

Every PAC tool I could find forges from scratch or from a template. Mimikatz, Rubeus, and Impacket's ticketer all build a PAC from the ground up, letting me set the groups and extra SIDs in `KERB_VALIDATION_INFO` and then signing the result. That is the right shape for a Golden or Silver ticket, but it is the wrong shape for studying the validator. A forged PAC tells me what a KDC would mint. It does not tell me what a domain controller will *accept* when a single field is wrong and everything else is genuine.

The primitive I wanted is the opposite: take a legitimately issued ticket, change exactly one buffer, one field, or one signature, leave the rest byte-for-byte intact, and see who notices. If I can change the UPN_DNS SID while leaving `LOGON_INFO` untouched, and both are still under valid signatures, then any rejection is the validator reconciling the two, not a broken checksum. That precision is what turns a ticket generator into a validator probe, and it is what `PACMutator` is built to do.

## The raw-container model

The core design decision is that `PACMutator` never round-trips a buffer's contents through an NDR re-encoder. Re-marshalling a PAC through a decode and re-encode cycle changes padding, pointer ordering, and alignment in ways that are invisible at the struct level but fatal at the byte level, and any of those differences will break a signature I did not mean to touch. So the tool holds each buffer as raw bytes and reflows the container by recomputing only the `PAC_INFO_BUFFER` table, the offsets, sizes, and count, around the bytes it was given.

The payoff is a hard invariant I can gate on: an unmutated ticket must reflow to a byte-identical copy of the original. If it does not, the tool is corrupting something on its own, and no result downstream can be trusted. Every session starts by confirming that identity round trip before any mutation runs. It sounds trivial, but it is the difference between a rejection that means something and a rejection that is my own bug.

## Independent per-signature control

The second decision is that each of the four signatures is controlled independently. This is the heart of the tool. For any given experiment I decide, per signature, whether to leave it valid, recompute it, zero its bytes, or strip the whole buffer. I recompute the one signature I can forge, the server signature, with the service key I hold, and I leave the krbtgt-keyed ones in whatever state the experiment calls for.

On the tickets I tested against Windows Server 2025, the server signature is an HMAC-SHA1-96-AES256 checksum, cksumtype 16, computed over the whole PAC with only the server and KDC checksum fields zeroed. I confirmed that my signing code reproduces the domain controller's server signature byte-for-byte before trusting it, the same way I gate the container round trip. Because I hold the target service key but not krbtgt, the asymmetry is fixed and total: I can always produce a valid server signature, and I can never produce a valid krbtgt one. Every experiment in this research is built on that asymmetry, and it is exactly the asymmetry a real attacker with a stolen service key would face.

## The differential method

A single accept-or-reject verdict is not enough, because Windows validates a PAC differently depending on who is checking it. A service running as Local System, Network Service, or with `SeTcbPrivilege` skips the domain-controller round trip and checks only the server signature it can verify itself. A plain domain-user service has no such shortcut, so it triggers full validation, where the domain controller verifies the krbtgt signatures and reconciles the identity. The same mutated ticket can sail through the first and die at the second.

So I run every mutation through two oracles and record the pair of verdicts. The signature-only oracle is an SMB service running as Local System. The full-validation oracle is a service running as a plain domain account, `svc-pac`, with no `SeTcbPrivilege`, which I confirm on every single run because a privileged context would silently invalidate the result.

<svg width="100%" viewBox="0 0 680 430" role="img"><title>The differential method: one mutation, two oracles, four outcomes</title><desc>A single mutated ticket is sent to a signature-only service and a full-validation service; the pair of verdicts classifies the mutation.</desc>
<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></marker></defs>
<g class="c-purple"><rect x="250" y="30" width="180" height="52" rx="8" stroke-width="0.5"/><text class="th" x="340" y="51" text-anchor="middle" dominant-baseline="central">Mutated ticket</text><text class="ts" x="340" y="67" text-anchor="middle" dominant-baseline="central">One field changed</text></g>
<line x1="300" y1="82" x2="180" y2="120" class="arr" marker-end="url(#arrow)"/>
<line x1="380" y1="82" x2="500" y2="120" class="arr" marker-end="url(#arrow)"/>
<g class="c-blue"><rect x="60" y="122" width="230" height="56" rx="8" stroke-width="0.5"/><text class="th" x="175" y="143" text-anchor="middle" dominant-baseline="central">Signature-only oracle</text><text class="ts" x="175" y="161" text-anchor="middle" dominant-baseline="central">Local System, no DC round trip</text></g>
<g class="c-teal"><rect x="390" y="122" width="230" height="56" rx="8" stroke-width="0.5"/><text class="th" x="505" y="143" text-anchor="middle" dominant-baseline="central">Full-validation oracle</text><text class="ts" x="505" y="161" text-anchor="middle" dominant-baseline="central">svc-pac, forces DC check</text></g>
<g class="c-gray"><rect x="60" y="230" width="560" height="170" rx="12" stroke-width="0.5"/><text class="th" x="80" y="256">Verdict pair classifies the mutation</text></g>
<g class="c-green"><rect x="84" y="276" width="512" height="30" rx="6" stroke-width="0.5"/><text class="ts" x="100" y="291" dominant-baseline="central">accept, accept: forgery full validation missed (the finding)</text></g>
<g class="c-amber"><rect x="84" y="312" width="512" height="30" rx="6" stroke-width="0.5"/><text class="ts" x="100" y="327" dominant-baseline="central">accept, reject: works only against Local System services</text></g>
<g class="c-gray"><rect x="84" y="348" width="512" height="30" rx="6" stroke-width="0.5"/><text class="ts" x="100" y="363" dominant-baseline="central">reject, reject: dead end, both paths catch it</text></g>
<line x1="175" y1="178" x2="175" y2="228" class="arr" marker-end="url(#arrow)"/>
<line x1="505" y1="178" x2="505" y2="228" class="arr" marker-end="url(#arrow)"/>
</svg>

The pair is the whole point. A mutation both paths reject is a dead end. A mutation the signature-only path accepts but full validation rejects maps the exploitability of the Silver-Ticket-adjacent surface: it works against Local System services and dies at a real domain controller. The prize is the mutation that both accept, because that is a forgery full validation failed to catch. Reducing the entire hunt to "find the accept-accept cell" is what makes the method tractable.

## The oracle trust gate

An accept-or-reject oracle is worthless until it is proven, because a broken pipeline rejects everything and a broken pipeline that accepts everything is worse. So before any real test I run three control tokens through the full-validation path. An unmutated rebuild must be accepted. A token with a deliberately corrupted server signature must be rejected, which proves the pipeline actually delivers my bytes rather than silently re-requesting a clean ticket. A known-bad mutation, a RID swap with a stale KDC signature, must be rejected, which proves the oracle agrees with ground truth on a case I already understand.

Accept, reject, reject means the token-to-SSPI-to-validate pipeline is faithful and the service is genuinely non-privileged. I then re-run the unmutated control inside every later batch as a canary. If it ever fails to accept, that whole batch is thrown out and I fix the environment before reading a single verdict. That discipline earned its keep more than once: an entire batch of rejections that looked like a hardened validator turned out to be an expired ticket, caught only because the canary failed alongside everything else.

## What it is for

`PACMutator` is a research instrument for characterizing a validator, not an exploit. It needs the target service key, which means it models a post-compromise position, and its output is a map of what a domain controller checks rather than a way to bypass those checks. The next post is that map: what Windows Server 2025 full PAC validation actually verifies, tested field by field.
