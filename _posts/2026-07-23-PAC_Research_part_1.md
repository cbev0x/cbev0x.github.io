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

![](/assets/img/2026-07-23-PAC_Research/1.png)

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

![](/assets/img/2026-07-23-PAC_Research/2.png)

The pair is the whole point. A mutation both paths reject is a dead end. A mutation the signature-only path accepts but full validation rejects maps the exploitability of the Silver-Ticket-adjacent surface: it works against Local System services and dies at a real domain controller. The prize is the mutation that both accept, because that is a forgery full validation failed to catch. Reducing the entire hunt to "find the accept-accept cell" is what makes the method tractable.

## The oracle trust gate

An accept-or-reject oracle is worthless until it is proven, because a broken pipeline rejects everything and a broken pipeline that accepts everything is worse. So before any real test I run three control tokens through the full-validation path. An unmutated rebuild must be accepted. A token with a deliberately corrupted server signature must be rejected, which proves the pipeline actually delivers my bytes rather than silently re-requesting a clean ticket. A known-bad mutation, a RID swap with a stale KDC signature, must be rejected, which proves the oracle agrees with ground truth on a case I already understand.

Accept, reject, reject means the token-to-SSPI-to-validate pipeline is faithful and the service is genuinely non-privileged. I then re-run the unmutated control inside every later batch as a canary. If it ever fails to accept, that whole batch is thrown out and I fix the environment before reading a single verdict. That discipline earned its keep more than once: an entire batch of rejections that looked like a hardened validator turned out to be an expired ticket, caught only because the canary failed alongside everything else.

## What it is for

`PACMutator` is a research instrument for characterizing a validator, not an exploit. It needs the target service key, which means it models a post-compromise position, and its output is a map of what a domain controller checks rather than a way to bypass those checks. The next post is that map: what Windows Server 2025 full PAC validation actually verifies, tested field by field.
