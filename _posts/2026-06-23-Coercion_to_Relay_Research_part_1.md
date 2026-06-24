---
title: "Coercion-to-Relay, Part 1: Fundamentals"
date: 2026-06-23
categories: [Personal]
tags: [Windows, Active Directory, Relay, Privilege Escalation, Research]
published: true
---

Every technique in this series traces back to one design decision in Windows authentication: a machine will authenticate to whatever endpoint it's told to connect to, and it has no way to verify that endpoint is the one it actually meant to reach. Coercion abuses the first half of that sentence. Relay abuses the second.

## Authentication coercion

Coercion is the act of forcing a remote machine, almost always a domain controller, to initiate an authenticated connection back to a host the attacker controls. The DC doesn't get compromised in this step. It just gets tricked into authenticating somewhere it shouldn't, and the attacker captures that authentication attempt instead of letting it land.

The mechanism is consistent across every primitive in this category: an RPC call exists in some legitimate Windows service that takes a UNC path or file path as a parameter, and the service doesn't validate that the path points somewhere reasonable. Point it at an attacker-controlled IP, and the calling machine account tries to authenticate to that IP over SMB or HTTP, using its own machine credentials. Since the call is part of a documented, working protocol, the DC isn't doing anything wrong by its own logic. It's doing exactly what the protocol says to do.

This matters because it means coercion isn't really a vulnerability class in the normal sense. It's a category of legitimate functionality that has an authentication side effect attackers can redirect. That's also why Microsoft has been reluctant to patch most of these primitives outright: the underlying RPC calls have legitimate uses, and the fix that actually matters lives on the relay side, not the coercion side.

## The four primitives

### PrinterBug (MS-RPRN)

The oldest of the four, predating the others by years. MS-RPRN is the Print System Remote Protocol. It exposes an RPC method, `RpcRemoteFindFirstPrinterChangeNotificationEx`, intended to let a print client register for notifications when a printer's state changes on a remote print server. The notification target is supplied by the caller as a UNC path.

Point that UNC path at an attacker-controlled listener, and the target machine's print spooler service tries to authenticate to it to deliver the (nonexistent) notification. The Print Spooler service runs as SYSTEM and is enabled by default on domain controllers in most environments, which is what makes this attractive. The authentication that lands at the attacker's listener carries the DC's machine account credentials.

This requires the spooler service to be running and reachable, which is also the primary mitigation: disabling Print Spooler on DCs (a long-standing recommendation independent of this specific abuse) closes the primitive entirely.

### PetitPotam (MS-EFSR)

MS-EFSR is the Encrypting File System Remote Protocol, intended to let clients perform remote EFS operations. The abused method is `EfsRpcOpenFileRaw`, which opens a file for backup or restore and, like the spooler call, accepts a path that can be redirected to a remote UNC location.

The practical difference from PrinterBug is reach: EFSRPC doesn't depend on the spooler service, and several of its RPC endpoints are reachable without prior authentication on unpatched systems, which is why PetitPotam got more attention and a faster (if incomplete) Microsoft response than the others. The patch closed the anonymous path. The call still works against an authenticated session, which is the form that matters for an engagement where you already have a foothold.

### ShadowCoerce (MS-FSRVP)

MS-FSRVP is the File Server Remote VSS Protocol, used by file servers to coordinate shadow copy creation for SMB shares so backups can be taken consistently. The protocol involves a sequence of RPC calls to create and expose a shadow copy, and one of those calls, `RequestShadowCopyAreaPath`, supplies a path the receiving server treats as a location to communicate back to.

This one is narrower in applicability than PetitPotam: it requires the File Server VSS Agent Service to be installed and running, which is not a default state on most domain controllers, though it's common enough on file servers that sit in scope during an engagement. Where it applies, the mechanism is the same forced-authentication pattern.

### DFSCoerce (MS-DFSNM)

MS-DFSNM is the Distributed File System Namespace Management Protocol, used to configure and query DFS namespace links. The abused call is `NetrDfsRemoveStdRoot` (and related namespace management methods), which again accepts a server path parameter that the target machine uses to attempt a connection.

DFSCoerce was published specifically to route around the mitigations operators had started applying to the first three primitives. If Spooler is disabled, RPC filters block EFSRPC, and the VSS agent service isn't installed, DFSNM is frequently still reachable, because DFS namespace services are foundational AD infrastructure and disabling them isn't a realistic mitigation in most environments. This is the primitive that's hardest to fully close through service removal alone.

## NTLM relay

Coercion gets you an authentication attempt arriving at a listener you control. Relay is what you do with it.

NTLM authentication is a challenge-response protocol. When a client authenticates to a server, the server issues a challenge, the client encrypts that challenge using a key derived from its password hash, and returns the response. Critically, in the classic protocol, the server validating that response doesn't have to be the server the client originally intended to talk to, and the protocol includes no binding between the authentication exchange and the specific TLS or transport-layer session it travels over, unless something explicitly adds that binding.

A relay attacker sits in the middle of this exchange functionally, without needing to be on-path on the network. The coerced machine connects to the attacker's listener and starts an NTLM negotiation, believing it's talking to whatever service was specified in the coerced path. The attacker's relay tool (ntlmrelayx, from Impacket, is the standard tool here) takes that incoming negotiation and immediately opens a second, separate connection to the real target service, forwarding the challenge and response through in real time. From the target service's perspective, it's just authenticating the coerced machine account normally. It has no way to know the request was relayed rather than sent directly.

The reason this chain ends in domain compromise so often is the choice of relay target. Relaying a DC machine account's authentication to LDAP gives you the ability to perform privileged directory operations as that DC. Relaying it to an AD CS web enrollment endpoint (the ESC8 path) gets you a certificate for the DC account, which converts into a TGT and from there into full domain control. Relaying to SMB gets you a session on whatever share that target machine account had to expose.

## Why every defense in this space targets relay, not coercion

Microsoft's posture, stated plainly across several advisories, is that authenticated forced-authentication calls are not bugs. A domain user causing a machine account to authenticate somewhere is functioning as designed. The fix Microsoft endorses is making sure the authentication, once captured, can't be usefully relayed anywhere.

Three mechanisms do that job, each closing a different gap:

**Signing** (SMB signing, LDAP signing) cryptographically signs every message in the session using a key derived from the session itself. A relayed session has a different underlying session key than the one the relay target expects, so a signed connection fails the moment the attacker tries to forward traffic through it, even though the NTLM challenge-response itself succeeded.

**Channel binding** (LDAP channel binding tokens, EPA for HTTP/AD CS) ties the application-layer authentication to the specific TLS channel it arrived on. This specifically closes the relay-to-LDAPS and relay-to-ADCS-web-enrollment paths, where signing alone doesn't apply because the transport is already encrypted and the attacker isn't forging the TLS layer, just relaying what's inside it.

**EPA** is really channel binding's name when applied to HTTP-based services, most relevantly AD CS web enrollment.

None of these mechanisms touch the coercion primitives themselves. A fully patched, fully updated domain controller in 2026 can still have its machine account coerced into authenticating to an attacker by all four primitives covered above. What determines whether that coercion turns into domain compromise is entirely on the relay side: whether the target protocol enforces signing, whether channel binding is configured, whether EPA is enabled on the CA's web enrollment endpoint.

The pace at which these defenses actually became defaults tells the real story here:

![Timeline of LDAP and SMB default hardening from 2003 to 2025](/assets/img/2026-06-23-Coercion_to_Relay_Research/timeline.png)

Two decades pass between the first signing capability shipping and any of it being required by default, and even the 2025 row only applies to fresh installs, not the upgraded domain controllers most environments are actually running.

This reframes the interesting question for the rest of this series. The relevant variable is never simply whether PetitPotam itself is patched. It's whether a specific relay target, in a specific environment, enforces the protection that breaks the relay. That question has a different answer for every protocol, every Windows version, and every administrator's actual configuration choices, which is exactly what the matrix in part 3 sets out to answer with real lab data rather than assumptions.

## What's next

Part 2 covers relay target mechanics in more depth: LDAP versus LDAPS behavior differences, what ESC8 actually requires on the CA side, and the SMB signing negotiation sequence in detail. Part 3 is the matrix itself, built and tested against a custom AD environment across multiple Windows Server baselines, with the OPSEC and detection findings that come out of running it.
