---
title: "Kerberos to an IP Address, Part 3: Coercion Behavior and What a Ticket Exposes"
date: 2026-07-15
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Research]
published: false
---

Parts 1 and 2 stayed on the mechanism: Kerberos to an IP works, gated on an SPN existing, and
registering an arbitrary IP SPN requires unconstrained write over the target account rather than
the constrained self-write every machine holds. This part moves from "how the feature works" to
"how it behaves when a machine is pushed to use it."

A note on how this and the next part are written. The findings here touch adversarial behavior,
and the responsible way to publish that is to describe what was observed and what it means for
defenders, not to provide a build-a-relay walkthrough. So this part is deliberately behavioral.
It explains the effect, the evidence, and the impact boundary. It does not lay out target
selection, tooling, or an ordered procedure, and it was prepared with coordinated disclosure in
mind. A reader should come away understanding what happens and why it matters, not holding a
recipe.

## The question

Windows has a long-studied class of "authentication coercion" behaviors, where a machine can be
induced to authenticate outbound to a location another party influences. Historically, that
coerced authentication comes back as NTLM, which is exactly why coercion has been paired with
NTLM relay for years.

The interesting question for IP SPN is simple to state. In an estate that has enabled the
client-side setting from Part 1 as part of retiring NTLM, and where an IP-based SPN exists for
some address, what does a coerced machine produce when it is pushed toward that address? Does it
still fall to NTLM, or does the new Kerberos-to-IP path change the shape of the coerced
authentication?

## The observed behavior: coercion leads with Kerberos

With the client-side setting enabled on the target machine and an IP-based SPN registered for
the destination address, a coerced machine account no longer leads with NTLM. It leads with
Kerberos.

Concretely, the machine resolves the destination address to the registered SPN, requests a
service ticket for it from the domain controller in the normal way, and presents a Kerberos
AP-REQ toward that destination. This is visible on the wire as a standard Kerberos exchange, and
it is confirmed by the domain controller issuing the corresponding service ticket. The coerced
authentication that would previously have been an NTLM message is now a Kerberos authentication.

That is the core behavioral finding: the same setting that lets an estate replace NTLM fallback
with Kerberos for IP-based connections also changes coerced authentication from NTLM to Kerberos
when the destination carries an IP SPN. The feature does what it says, and coercion rides along
with it.

## It holds for both member servers and domain controllers

Two victim types were examined: an ordinary member server and a domain controller. The
expectation going in was that a domain controller's stronger default posture might change the
outcome. It did not change *this* part of the outcome. Both a member server and a domain
controller, under the conditions above, produced the Kerberos-led coerced authentication.

One reachability detail is worth stating because it is easy to overlook. Domain controllers run
the DFS Namespace service by default, because they host the SYSVOL and NETLOGON namespaces. That
makes the DFS-based coercion surface reachable on a domain controller out of the box, without
any additional role being installed, whereas an ordinary member server would need that role
present. This is a defender-relevant fact independent of IP SPN: DCs expose that particular
coercion surface by default.

## What the authentication exposes: the PAC

When a Kerberos service ticket is issued, it carries a Privilege Attribute Certificate (PAC), a
signed structure describing the authenticating account's identity and group memberships. A
coerced Kerberos authentication therefore carries the victim machine account's PAC, and
inspecting it shows exactly what a coerced machine discloses about itself.

For a member server, the PAC contents are modest:

```
EffectiveName : <server>$
UserId (RID)  : <machine account RID>
PrimaryGroup  : 515   (Domain Computers)
Groups        : [515]
```

That is routine identity information. A member server discloses that it is a computer account and
a member of Domain Computers, which is data any authenticated principal could already read from
the directory with an ordinary query. The disclosure is real but low value on its own.

For a domain controller, the same structure carries a more significant group:

```
EffectiveName : DC01$
UserId (RID)  : 1001
PrimaryGroup  : 516   (Domain Controllers)
Groups        : [516]
```

Group 516 is Domain Controllers, a Tier-0 group. So a coerced domain controller discloses,
through its PAC, that it authenticated as a domain controller account. This is a meaningfully
higher-value disclosure than the member case, and it is the reason the domain controller victim
is worth examining separately even though the coercion mechanism is the same.

## Bounding the impact honestly

It is important to be precise about what this disclosure is and is not, because the difference
decides severity.

What it is: a coerced machine authentication, delivered as Kerberos, whose PAC reveals the
victim machine account's identity and group membership. For a domain controller that includes
its Tier-0 group membership.

What it is not: a credential. The PAC is a signed description of an identity, not the account's
key. Receiving a coerced authentication does not hand over the victim's secrets, and it does not
by itself let the receiver act as the victim against other services. The well-known SIDs shown
above (515, 516) are public constants; the disclosure is that *this specific machine
authenticated*, plus its already-enumerable group context, not any new secret material.

The natural follow-on question, whether a coerced Kerberos authentication like this can be
turned into access against some other service (that is, relayed), is the subject of Part 4. The
short version, developed there with its mechanism, is that the property which makes Kerberos
tickets bound to a specific service key, together with signing and channel-binding enforcement
on default configurations, is what contains this. Part 4 explains why, and where the boundary
between "contained" and "not contained" actually sits, because that boundary is the real
defensive lesson of the series.

## Where this leaves us

The behavioral finding of this part: enabling the IP SPN client path as part of retiring NTLM
changes coerced authentication from NTLM to Kerberos when the destination carries an IP SPN, for
both member servers and domain controllers, and the resulting authentication discloses the
victim machine account's PAC. For a domain controller that PAC carries Tier-0 group membership,
which raises the disclosure stakes even though no credential is exposed.

That is a new behavior worth understanding as estates turn this path on, and it sits in the same
family as other recent Kerberos coercion research. Part 4 places it in that context, explains why
it is contained on a properly configured estate, and turns to the part defenders can act on
directly: the controls that stop it, and a detection gap that makes this activity quieter than it
should be in the usual logs.

---

*This series documents original lab research conducted in an isolated environment. It is
educational and defensive in intent, and the adversarial-behavior parts are written to convey
mechanism and impact rather than to serve as a reproduction guide.*
