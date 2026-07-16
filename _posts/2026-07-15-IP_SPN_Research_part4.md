---
title: "Kerberos to an IP Address, Part 4: Why It Is Contained, and Where Detection Falls Short"
date: 2026-07-15
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Research]
published: true
---

Part 3 showed that enabling the IP SPN client path changes coerced authentication from NTLM to
Kerberos when the destination carries an IP SPN, for both member servers and domain controllers,
and that the resulting authentication discloses the victim machine account's PAC. It ended on the
question that decides how much any of this matters: can that coerced Kerberos authentication be
turned into access against another service?

This part answers it, places the answer in the context of the recent Kerberos relay research it
belongs alongside, and then turns to the thing defenders can act on directly. It is written as
containment analysis and detection guidance. There is no exploitation procedure here, because the
useful output is the opposite: which controls stop this, and where the usual logs go quiet.

## The relay question, and why the answer is "contained by default"

Relaying an authentication means taking a credential a victim produced for one destination and
presenting it to a different service to gain access there. NTLM relay works because NTLM
authentication is not cryptographically bound to a specific target. Kerberos has historically
resisted relay for the opposite reason: a Kerberos service ticket is encrypted with the key of
the specific service account that owns the requested SPN. A ticket minted for one service simply
cannot be decrypted by another, because the second service holds a different key.

That binding is what contains the IP SPN coercion behavior. A coerced machine resolves the
destination address to whatever SPN is registered for it and obtains a ticket bound to that
SPN's owning account. If that account is one an attacker controls, the ticket can be decrypted
and its PAC read (the disclosure covered in Part 3), but the ticket is bound to the attacker's
own service identity and is not valid against any other service. It cannot be re-pointed at a
real target, because the real target's key would be required to produce a ticket it would accept.

There is a second, independent control that matters even in the cases where a key match could
otherwise occur: signing and channel binding. Modern Windows services can require that the
authenticated channel be integrity-protected (SMB signing) or bound to the transport (channel
binding / Extended Protection for Authentication). When a service enforces these, a relayed
authentication is rejected at channel establishment regardless of the ticket, because the relayer
cannot satisfy the integrity or binding requirement for a session it is merely forwarding.

On a current, patched Windows Server 2025 estate, both of these hold by default. SMB signing is
required, LDAP signing is enforced, and the relevant services reject unsigned or unbound
authentication. In testing, every default service posture rejected the relayed authentication,
and the only way to observe an accepted relay was to deliberately misconfigure a target by
disabling required signing, which is precisely the point: the acceptance is a function of the
misconfiguration, not of the feature.

So the honest severity statement is that IP SPN, on a properly configured estate, does not hand
an attacker a new relay primitive. It changes the shape of coerced authentication and it
discloses a PAC, but the SPN-to-key binding and default signing/CBT enforcement contain the
relay. That is a reassuring result, and it is worth stating as clearly as the risks, because
overclaiming a contained behavior helps no one.

## Where this sits in the current research landscape

This work does not exist in isolation. The last year has produced a series of results probing
exactly the assumption that Kerberos is inherently relay-proof, and IP SPN belongs in that family.
Anyone evaluating the IP SPN behavior should read it against these:

- **CVE-2026-20929** (DNS CNAME abuse). A Windows Kerberos client that receives a CNAME follows
  the alias and builds its service-ticket request using the CNAME hostname as the SPN. An on-path
  attacker who can influence DNS can steer the victim to request a ticket for an attacker-chosen
  SPN. Microsoft's January 2026 response added channel binding support to HTTP.sys, which reduces
  exposure for HTTP relay specifically, but the underlying CNAME coercion of the SPN choice
  remains. Default configurations of Windows 10, 11, Server 2022, and Server 2025 were reported
  affected when signing and binding were not enforced.

- **CVE-2026-26128** (reflection via SPN normalization mismatch). Research abusing a difference in
  how the domain controller normalizes a service name during SPN lookup versus how the DNS client
  compares names, allowing a crafted record to map to a real machine SPN while still triggering a
  DNS lookup, yielding the machine's own ticket to a controlled endpoint. It reportedly broke an
  earlier fix in this space.

- **CVE-2025-58726 and the "Ghost SPN" work**. Abuse of unresolved HOST/ and CIFS/ SPNs on
  computer accounts, combined with DNS record creation and coercion, and the associated finding
  that many services validate the hostname portion of an SPN rather than the service-class prefix
  (so an SMB service may accept a ticket presented for a CIFS or HOST class, and so on).

The common thread across all of these is that Kerberos relay becomes possible when an attacker
can influence which SPN a client requests *and* the target service does not enforce signing or
channel binding. IP SPN is another way to influence SPN selection, distinguished by the fact that
it registers the SPN directly in the directory rather than relying on DNS manipulation. Its relay
outcome follows the same rule as the rest: it depends on the ticket being bound to a real
target's key and on that target lacking signing or binding enforcement. On default Server 2025,
those conditions are not met, which is why the behavior is contained.

## The defensive controls that matter

The controls that contain this are not new, and that is good news, because it means existing
hardening guidance already covers them. Stated as actions:

- **Enforce SMB signing.** Required signing rejects relayed SMB authentication outright. It is
  the single most effective control against this class, and it is the default on current Windows
  Server, so the action for most environments is to confirm it has not been relaxed.

- **Enforce LDAP signing and channel binding.** The same principle for directory services. LDAP
  signing enforcement was observed rejecting relayed authentication in testing.

- **Enforce Extended Protection for Authentication (channel binding) on HTTP-based services,
  especially AD CS web enrollment.** Certificate enrollment endpoints are a classic relay target,
  and EPA is the control that closes them. Recent Server builds enforce it by default on the web
  enrollment endpoint; the action is to confirm that default has not been turned off, because a
  relaxed enrollment endpoint is exactly the kind of misconfiguration that converts a contained
  behavior into an exploitable one.

- **Audit unconstrained write over computer objects' SPN attribute.** From Part 2, placing an
  arbitrary IP SPN requires full `WriteProperty` / `GenericWrite` / `GenericAll` over the target.
  That ACL edge is already dangerous for other reasons (RBCD, shadow credentials), and it is the
  precondition here too. If you are already hunting for it, you are already covering this.

The through-line is that signing and channel binding are the controls that make Kerberos relay,
of any flavor including this one, fail. The IP SPN behavior is one more reason to confirm they are
enforced, not a reason to invent new defenses.

## The detection gap

The most actionable finding for a defender, and the one worth the most attention, is not about
whether the attack works. It is about whether you can see it.

When a client requests a Kerberos service ticket, the domain controller records event 4769 (a
Kerberos service ticket was requested) in its Security log. This is the primary DC-side artifact
for Kerberos service-ticket activity, and detection content across the industry keys on it.

The gap is in what the event records. For an IP-based SPN request, the 4769 event's service
fields identify the *account that owns the SPN*, not the SPN string that was requested. The
requested IP literal does not appear in the event. Examined at the raw event level, the only
address recorded is the client's source address; the destination IP that the client asked for a
ticket to is absent entirely. A service-ticket request for an IP-based SPN is, in the 4769 event,
indistinguishable from an ordinary hostname-based request to the same machine account.

The practical consequence is a visibility hole. On the client side, when Kerberos-to-IP succeeds,
no NTLM fallback event is generated, so the NTLM operational channel that would otherwise flag an
IP-based authentication stays silent (that channel only records the *failure* cases, reasons 7
and 6 from Part 1, which do carry the IP in plaintext). On the DC side, the 4769 fires but does
not contain the IP. So the moment an estate enables the IP SPN path, an entire category of
authentication, Kerberos to an IP address, becomes difficult to distinguish in the two log
sources defenders most rely on for Kerberos and NTLM activity.

This is the piece most worth acting on. As NTLM deprecation drives adoption of the IP SPN path,
the assumption baked into a lot of existing detection, that Kerberos to an IP address does not
happen, silently becomes false, and the telemetry that would confirm it is either absent (the
NTLM channel, on success) or does not carry the distinguishing detail (the 4769, always). Teams
building or tuning Kerberos detection should be aware that IP-based service-ticket activity is
under-represented in standard telemetry, and should treat the presence of IP-based SPNs in the
directory, and the enabling of the client-side setting, as conditions that change what their
existing rules can see.

## Closing the series

Across four parts: Kerberos to an IP address is the familiar SPN-to-key model applied to an
address, gated on a client setting and on an SPN existing (Part 1). Registering an arbitrary IP
SPN is blocked for the low-privilege self-write by a validated-write host-match, and requires
unconstrained write over the target, an already-dangerous permission (Part 2). Coercion under
these conditions produces Kerberos rather than NTLM and discloses the victim's PAC, more
significantly for a domain controller than a member server (Part 3). And the relay is contained
on a default estate by the SPN-to-key binding and by signing and channel-binding enforcement,
while the activity is harder to detect than it should be because the standard logs either go
silent or omit the IP (Part 4).

The overall picture is measured rather than alarming. IP SPN is a legitimate feature that will
become more common as NTLM is retired, its worst-case abuse is contained by controls most
environments already have, and the most important defensive takeaway is to keep those controls
enforced and to understand that this activity is quiet in the usual telemetry. That last point,
the detection gap, is the one this research most wants defenders to walk away with.

---

*This series documents original lab research conducted in an isolated environment, and is
educational and defensive in intent. Findings that warranted vendor attention were handled
through coordinated disclosure.*
