---
title: "Windows Authentication Reflection, Part 1: The Mechanic and Its Lineage"
date: 2026-07-07
categories: [Personal]
tags: [Windows, Active Directory, Coercion, Privilege Escalation, Research]
published: true
---

Authentication reflection is a family of attacks that keeps getting declared dead and keeps coming back. It looks like a footnote to NTLM relay until you examine the mechanic, and then it resolves into something distinct: a primitive with a decade-long habit of resurfacing every time Microsoft closes the previous instance. This is part one of two. It builds the concept from the ground up, covering what reflection is, why the Windows authentication stack makes it possible, and how one core weakness has re-emerged across twelve years of CVEs. Part two moves into the lab, where we reproduce the most recent instance on Windows Server 2025 and work out what it looks like from the defender's side.

## Reflection is not relay with fewer hops

A classic NTLM relay coerces host A into authenticating to the attacker, then passes A's authentication through to a different service on host B. A never learns it spoke to B, and the attacker rides whatever session B grants. Reflection keeps the coercion and the relay but collapses the destination back onto the source. A is coerced, and A's authentication is relayed to a service on A itself. A authenticates to A.

What makes that worth doing, rather than a curiosity, is what the reflected identity can reach. The coerced principal is almost always the machine account, and a machine account is privileged on its own host. Bouncing that identity back at a service running on the same box hands the machine its own credentials and asks it to act on them locally. Done right, that yields a SYSTEM context on the target. This is why reflection reads as local privilege escalation, and why, when chained with coercion from a remote foothold, it reads as remote code execution.

## Nothing gets cracked

Reflection is easy to file next to the Responder-style capture-and-crack workflow, and that is a mistake worth heading off early. Coercion yields the machine account, and machine account passwords are roughly 120 characters of random data, rotated every 30 days by default. Unless you're sitting under a rainbow, that is not cracking offline, ever. Reflection sidesteps the question because the secret is never needed. The live authentication is relayed in real time and the target validates it against itself. The entire attack lives inside a single authentication exchange, start to finish.

That property is also why reflection survives hardening that stops other attacks. There is no weak password to find, no hash to submit to a wordlist, no downgrade to force. There is only a legitimate authentication redirected back at its own origin.

## The mechanic: local authentication and the empty type-3

Reflection keeps returning because of how Windows handles authentication to itself. When a Windows process authenticates over NTLM, the stack checks whether the target is the local machine, and if it decides the target is local it takes a shortcut. That shortcut is a local authentication path that does not perform the full challenge-and-response verification a remote authentication would. Rather than proving knowledge of the secret across the wire, the local path trusts the context and inserts the resulting token directly into memory. That token carries the privileges of the caller, and when the caller is a SYSTEM-level service, so is the token.

The shortcut becomes an attack primitive because of what happens to the messages. On the local authentication path, the NTLM_AUTHENTICATE message, the type-3 in the three-message handshake, comes across effectively empty. The fields that would normally anchor the exchange against tampering are absent, so the message integrity code, the AV-pair flags, and the NtProofStr are never validated. Those validations are what would otherwise catch a manipulated or replayed authentication. On the local path, they do not run.

That single skip is the root of the whole class. Because the integrity code is not checked, an authentication steered down the local path can have its protective flags stripped without breaking anything the server verifies. This is what lets a reflected authentication drop the signing flag and slip past defenses that were supposed to require signed sessions. Over channels that would otherwise enforce channel binding, such as LDAPS or HTTPS, the same emptiness means the binding check has nothing to enforce against. The local path is a hole in the middle of the authentication guarantees, and reflection is the practice of routing a network authentication into it.

Everything downstream is a variation on one question: how is a remote authentication convinced to be treated as local?

## Fooling the locality check

The answer, for the modern era of this attack, abuses how Windows canonicalizes a target name before it decides locality. James Forshaw documented the primitive that makes it work, built on `CredMarshalTargetInfo`. Marshalled target information, a base64-encoded blob, can be appended after a hostname. When Windows parses the name to decide whether the target is local, it strips the marshalled portion and compares only the surviving hostname. If that surviving hostname resolves to something the machine considers itself, the stack engages the local path, even though the name actually used pointed the authentication at an attacker-controlled endpoint.

The operational chain follows from that. We plant a DNS record for the crafted name, coerce a privileged service to authenticate to it, and the authentication leaves the box aimed at the attacker while canonicalization later concludes the target was local. Relayed back, the local path engages and the empty type-3 does the rest. Any domain user can typically plant the required record, and coercion needs no special privilege, so the chain starts from an ordinary foothold and ends at SYSTEM.

## Lineage: one weakness, many instances

What makes reflection worth a two-part writeup rather than a single CVE walkthrough is its history. This is not a new bug. It is an old class that Microsoft has patched, instance by instance, for over a decade, and each patch has closed a specific route to the local path while leaving the path itself intact.

The first well-known death was same-protocol SMB reflection, closed by MS08-068. The fix was narrow and clever: the SMB stack began tracking the challenges it issued and rejecting any client response that replayed one of its own challenges. An SMB authentication reflected straight back at the same SMB service met a server that recognized its own challenge coming home and refused. For years that was treated as the end of SMB reflection.

The weakness in that fix was scope. Challenge tracking lived inside a single protocol stack and did not coordinate across protocols, so reflection did not die, it just moved. Instead of SMB back to SMB, attackers reflected across protocol boundaries: an SMB authentication relayed to an HTTP endpoint such as AD CS web enrollment, or to LDAP on a domain controller. The HTTP endpoint never saw the SMB stack's challenge cache, so it had no basis to reject the reflected authentication. Subsequent patches chased the cross-protocol variants, and the pattern held: each fix addressed the pairing in front of it, and the class waited.

In 2025 the primitive came back into the spotlight. Synacktiv's work on CVE-2025-33073 revived SMB-to-SMB reflection by using the marshalled-name trick to make a remote authentication read as local, defeating the old challenge-tracking logic entirely. On any machine that did not enforce inbound SMB signing, this delivered command execution as SYSTEM. Microsoft's fix landed in June 2025 and was, once again, narrow. It taught the SMB client to call `CredUnmarshalTargetInfo` and reject any target name carrying marshalled information. That fix lived in the SMB client path and nowhere else.

That narrowness is the story of everything that followed. Andrea Pierini's research on ghost SPNs, later assigned CVE-2025-58726, reached the local path through service principal names pointing at hostnames not registered in DNS, and was fixed server-side with loopback validation rather than in the client. His work on the Server 2025 print notification callback, CVE-2025-54918, exploited the fact that Microsoft had moved that callback onto DCE/RPC, which still honored the marshalled-name trick and, better for an attacker, did not even require the DNS and SPN games because a bare attacker address was enough to negotiate local authentication. That fix forced the message integrity code to always be calculated and channel bindings to always be evaluated on that path. Each of these was a real patch, and each closed one more doorway into the same room.

The most recent instance at the time of writing is CVE-2026-24294, again from Synacktiv, patched in March 2026. It needs no marshalled hostname at all. It abuses two SMB client behaviors that recent Windows versions introduced: the ability to connect to an SMB share on an arbitrary TCP port, and connection reuse through SMB multiplexing. A local SMB server is stood up on a nonstandard port, a share is mounted from it so the client establishes and keeps a TCP connection, and then a privileged service is coerced to the same path so its authentication rides the connection the attacker already controls. It works by default on Windows Server 2025, and notably it does not work on Windows 11 24H2, because 24H2 enforces SMB signing, and signing remains the durable control that breaks the relay regardless of how the local path is reached.

One boundary is worth naming because it clarifies the mechanic. Reflecting DCOM back to SMB does not work, because the SMB client honors a flag that strips the service principal name on a loopback target and refuses to treat the reflected authentication as local. The class is broad but not unlimited, and the pairs that work say as much about the defenses as the pairs that do not.

## The instance gets patched, not the class

Line those fixes up and the shape is unmistakable. MS08-068 closed same-protocol SMB and left cross-protocol open. The cross-protocol patches closed pairings and left the marshalled-name trick open. CVE-2025-33073's fix closed the SMB client path and left ghost SPNs, the DCE/RPC callback, and the arbitrary-port behavior open. Every one of those was a correct patch for the instance in front of Microsoft, and every one left the underlying weakness, the local authentication path with its empty type-3 and skipped integrity checks, exactly where it was.

That is the thesis to carry into part two. Authentication reflection is not a bug that gets fixed. It is a class, rooted in a design decision about how Windows authenticates to itself, and the CVEs are the visible waterline of a much older structure. Hunting the next instance is less about finding a new vulnerability than about finding a new route into an old one. Defending against it is the mirror image: chasing individual CVEs is a losing posture next to the controls that neutralize the class outright, which is where we spend most of our effort in part two. Enforce SMB signing, require channel binding and extended protection over TLS, cut off coercion surface, and move off NTLM where possible.

Part two builds a Windows Server 2025 lab, reproduces CVE-2026-24294 against it, and turns to the question that matters most for a defender: when this fires, what exactly shows up in the telemetry, and how do we catch it. Every result there is pinned to an exact build number, because on this topic, as this part should already make clear, the build number is the whole story.

## Acknowledgments and references

This piece stands on published research, and the class is legible only because of the people who took it apart in public. Any errors are mine.

- James Forshaw (@tiraniddo), on `CredMarshalTargetInfo` and relaying Kerberos authentication: https://www.tiraniddo.dev/2024/04/relaying-kerberos-authentication-from.html
- Synacktiv, on CVE-2025-33073 (NTLM reflection is dead, long live NTLM reflection): https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
- Synacktiv, on CVE-2026-24294 (bypassing Windows authentication reflection mitigations for SYSTEM shells, part 1): https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1
- Andrea Pierini (decoder), reflecting your authentication (reflection internals and the local-authentication mechanic): https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/
- Andrea Pierini (decoder), ghost SPNs and Kerberos reflection: https://www.semperis.com/blog/exploiting-ghost-spns-and-kerberos-reflection-for-smb-server-privilege-elevation/
- RedTeam Pentesting, reflective Kerberos relay attack: https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/
- Microsoft, KB5005413, mitigating NTLM relay attacks on AD CS: https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
