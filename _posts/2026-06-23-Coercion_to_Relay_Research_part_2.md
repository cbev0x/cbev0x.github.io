---
title: "Coercion-to-Relay, Part 2: Relay Target Mechanics"
date: 2026-06-23
categories: [Personal]
tags: [Windows, Active Directory, Relay, Privilege Escalation, Research]
published: true
---

Part 1 covered the shape of the chain: coercion produces an authentication attempt, relay forwards it somewhere useful, and the protections that matter all live on the relay side rather than the coercion side. This part goes one level deeper into each relay target, because "relay it to LDAP" and "relay it to LDAPS" are not the same attack with a different port number, and ESC8 has its own set of preconditions that have nothing to do with signing or channel binding at all.

## Relaying to LDAP and LDAPS

What you get from a successful LDAP relay depends on what the relayed identity has permission to do, but against a domain controller's own machine account, the standard outcomes are:

- Writing `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer object to set up resource-based constrained delegation, which then lets you impersonate any user (including Domain Admins) to that target via S4U2Self/S4U2Proxy
- Writing `msDS-KeyCredentialLink` on a target object to add a shadow credential, then authenticating as that principal via PKINIT
- If the relayed identity has sufficient rights, granting DCSync replication rights directly

None of that requires AD CS to be involved. It's a direct LDAP write using the relayed session, and it's why LDAP is usually the first relay target operators try once a coercion primitive is confirmed working.

The distinction between LDAP (port 389) and LDAPS (port 636) is where the protections diverge, and this is the part worth being precise about, since the two ports are protected by two different mechanisms:

**LDAP signing** protects port 389. Signing works by deriving a signature key from the session key established during the NTLM handshake. A relayed session has a different session key on the attacker's side than the real target expects, since the attacker is forwarding messages between two independent NTLM exchanges, not the same one. Once signing is enforced, the signature check fails immediately, regardless of whether the initial challenge-response succeeded. This is purely a transport-layer integrity check and has nothing to do with TLS.

**LDAP channel binding** protects port 636 (LDAPS), and it's a different mechanism solving a different problem. LDAPS is already encrypted by TLS, so message tampering isn't the concern; the concern is that the NTLM authentication happening inside the TLS tunnel has no cryptographic tie to that specific TLS session. Channel binding closes this by having the client include a hash of the TLS channel's properties (specifically, the server's certificate) inside the NTLM message itself. When a relay attacker forwards an NTLM exchange from one TLS session (the coerced victim's connection to the attacker) into a second TLS session (the attacker's connection to the real LDAPS target), the channel binding token computed for the first session doesn't match the second session's TLS properties, and the bind fails.

This is why a domain controller can have LDAP signing enforced while LDAPS channel binding is left at its old default, or vice versa. Treating "LDAP relay" as a single technique obscures this: an environment can be relay-resistant on one port and wide open on the other, and which one matters depends entirely on which port the relay tooling targets.

## Relaying to AD CS web enrollment (ESC8)

ESC8 is the name SpecterOps' Certified Pre-Owned research gave to relaying a coerced authentication into AD CS's HTTP-based certificate enrollment interface, and it's the highest-value relay target in this entire chain because the output is a certificate, and a certificate converts into a TGT.

The precondition list here is different in kind from the LDAP case, because AD CS web enrollment has its own independent set of insecure-by-default behaviors that exist regardless of signing or channel binding:

- The CA's web enrollment role (`certsrv`), when installed, listens over HTTP by default, not HTTPS, unless an administrator explicitly configures a certificate and binding for it. NTLM over plain HTTP has no equivalent to LDAP signing at all, so there's nothing protecting it unless EPA is added on top.
- Even when HTTPS is configured, Extended Protection for Authentication is not enabled on IIS by default. EPA on a web service does the same job channel binding does for LDAPS: it ties the NTLM exchange to the specific TLS session it arrived on, and without it, a relayed authentication over HTTPS succeeds exactly as cleanly as one over plain HTTP.
- The certificate template needs to permit the requesting identity to enroll and to specify Client Authentication as an EKU. The default `Machine` template, present in essentially every AD CS deployment, satisfies this for any domain-joined computer account, which includes the domain controller's own machine account that you just coerced.

The chain end to end: coerce the DC's machine account into authenticating to your relay listener, relay that authentication to the CA's web enrollment endpoint, request a certificate against the Machine template using the DC's own identity, receive a valid certificate for the DC computer account, then use that certificate with PKINIT to request a TGT for the DC account. From a TGT for a domain controller's machine account, DCSync and full domain compromise follow through well-documented paths that don't need restating here.

The mitigation surface is correspondingly narrower than the LDAP case: enable EPA on the CA's web enrollment IIS site, require HTTPS, or disable NTLM authentication on the CA entirely (Kerberos-only) if nothing in the environment depends on NTLM reaching it. None of the three involve "patching" anything; they're configuration choices on a role that ships permissive by default.

## Relaying to SMB

SMB relay is the oldest of the three targets and, after the 2025 default changes covered in the timeline notes, the most version-dependent.

SMB signing negotiation happens during session setup: client and server each advertise whether they support and/or require signing, and the more restrictive setting wins. Historically, the only default-enforced signing requirement applied to connections to the SYSVOL and NETLOGON shares specifically on domain controllers, which exist to deliver Group Policy and logon scripts and were judged sensitive enough to protect by default well before the rest of SMB traffic was. Every other SMB share, on domain controllers and especially on member servers, negotiated signing only if an administrator had explicitly turned it on.

This is why relaying SMB authentication to a member server (rather than back to the DC) has historically been such a reliable path to local admin or secrets-dump access: most file servers, application servers, and workstations in a typical environment never had signing enforced, because the only default protection was scoped narrowly to two specific DC shares. Windows Server 2025's change to require outbound SMB signing by default closes part of this gap going forward, but only for outbound connections and only on systems actually running 2025, which circles back to the upgrade-path problem from part 1: a 2019 or 2022 member server, even fully patched, keeps its old permissive SMB signing posture unless someone changes it.

## Treating relay targets as a grid, not a single technique

None of these three relay targets fail for the same reason. LDAP fails closed because of message signing. LDAPS fails closed because of channel binding tied to the TLS session. AD CS web enrollment fails closed because of EPA, a mechanism that does the same conceptual job as channel binding but is configured entirely separately and isn't on by default even when the rest of an environment is hardened. SMB fails closed only where an administrator (or, as of 2025, a fresh install) has actually turned signing on, and the default scope of that protection has historically been almost nothing.

This is the case for treating "is NTLM relay still a thing" as the wrong question entirely. Each relay target has its own protection mechanism, its own default posture, and its own version history, and a domain controller can be simultaneously hardened against one and wide open on another depending on which boxes an administrator happened to check. Part 3 builds that grid out against a custom AD environment, with each cell tested rather than assumed.

## What's next

Part 3 is the matrix: all four coercion primitives tested against all five relay targets, across multiple Windows Server baselines, with the result for each cell and the OPSEC findings that came out of capturing it in Elastic.
