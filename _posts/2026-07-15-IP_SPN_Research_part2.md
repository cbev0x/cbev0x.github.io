---
title: "Kerberos to an IP Address, Part 2: Who Can Register an IP SPN"
date: 2026-07-15
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Research]
published: true
---

Part 1 established that Kerberos to an IP address works, and that the single gate between a
failed local resolution and a working ticket is whether an IP-based SPN exists in the directory
for that address. That naturally raises the next question, and it is the one that decides how
much any of this matters in practice: who can actually register such an SPN?

The short answer turns out to be reassuring, but getting to it means walking through a
misleading error and a piece of directory validation that is easy to misread. This part is
still pure mechanism. No coercion, no relay. Just the registration boundary and what enforces
it.

## The question, framed correctly

An SPN like `host/192.168.1.50` is just a value in the `servicePrincipalName` attribute of some
account. So "can I register an IP SPN" is really "can I write that value onto an account." In
Active Directory, the answer to any "can I write this attribute" question is decided by the
DACL on the target object, and computer accounts have a specific and slightly unusual set of
default rights over their own `servicePrincipalName`. That detail is the whole story here.

The scenario worth testing is the one that would matter to an attacker: a low-privilege domain
user who has created a computer account (every authenticated user can, by default, up to the
`ms-DS-MachineAccountQuota` of 10). That user controls the computer account. Can they place an
arbitrary IP SPN on it?

## The misleading part: an SPN that looks rejected outright

The first result looks like AD flatly refusing IP SPNs. Attempting to write `host/<some-IP>` to
a controlled computer account, acting as that account or its creator, returns:

```
0x200b / 8203  ERROR_DS_INVALID_ATTRIBUTE_SYNTAX
```

Read literally, "invalid attribute syntax" suggests the IP-form SPN is malformed, that AD does
not accept an address where it wants a hostname. That reading is wrong, and it sent the early
part of this investigation down a false trail worth recounting, because the way it resolves is
the actual finding.

The tell is that the same value behaves differently depending on the target. Registering the
identical `host/<IP>` string onto a *real, domain-joined* computer account, as an administrator,
succeeds cleanly. The value is not malformed. AD stored it happily on one account and rejected
it with a syntax error on another. So the error is not really about syntax, and it is not really
about the IP. Something about the writer or the target differs.

## Isolating the variable

The way to resolve a "same value, different outcome" situation is to change one thing at a time.
Two comparisons settle it.

First, error codes across targets. Writing the IP SPN as a low-privilege user to an account that
user does *not* control returns a different, honest error:

```
0x2098 / 8344  Insufficient access rights to perform the operation.
```

That is a clean permissions denial. Meanwhile the *same* low-privilege user writing to an
account they *do* control returns the misleading `0x200b` syntax error. Two different failure
codes for what turns out to be the same underlying cause, which is exactly why the syntax error
misleads: on the controlled account, AD gets far enough to run a validation that the
uncontrolled account never reached.

Second, and decisively, the value type. On the controlled computer account, writing a
*hostname* SPN that matches the account's own name succeeds:

```
HOST/<account>.<domain>     -> accepted
MSSQLSvc/<account>.<domain> -> accepted (any service class, as long as the host matches)
```

while writing a hostname SPN that does *not* match the account, or the IP-form SPN, both fail
with the same `0x200b`:

```
HOST/some-unrelated-host    -> 0x200b
host/<some-IP>              -> 0x200b
```

The discriminator is not IP-versus-name. It is whether the SPN's host component matches the
account's own identity.

## The mechanism: the Validated-Write to servicePrincipalName

The rights that a computer account (and its creator) hold over the account's own
`servicePrincipalName` are not a plain `WriteProperty`. They hold a *validated write*, exposed
in the DACL as a `Self` right with the object type:

```
f3a64788-5306-11d1-a9c5-0000f80367c1   (Validated write to service principal name)
```

A validated write is a constrained write. Rather than letting the principal put any value into
the attribute, AD runs a built-in check and only permits values that pass it. For
`servicePrincipalName`, that check requires the SPN's host component to correspond to the
account's `dNSHostName` or `sAMAccountName`. A hostname SPN that matches the machine's own name
passes. An arbitrary hostname that belongs to some other host fails. And an IP literal, which
can never match a machine's own DNS name or SAM account name, fails the same way. The
`INVALID_ATTRIBUTE_SYNTAX` surfaced by the validated write is simply how that rejection presents;
it is not a comment on the IP format as such.

This is why the earlier administrator write to a real machine succeeded: an administrator does
not go through the validated `Self` write. `BUILTIN\Administrators` has full `WriteProperty` /
`GenericAll`, which bypasses the validation entirely and can place any SPN, IP-form included, on
any account.

## Confirming the boundary from the other direction

If the gate is "validated write cannot, full write can," then granting a low-privilege user an
explicit unconstrained write over a target's SPN attribute should let that user place the IP SPN
that the validated self-write refused. Testing exactly that, granting a plain user
`WriteProperty` on `servicePrincipalName` over a target computer, and then writing `host/<IP>`
as that user, succeeds.

So the picture is complete and consistent:

- A computer account's default self-write over its own SPN is a *validated* write. It enforces a
  host-match, which an arbitrary IP can never satisfy. Self-registration of an arbitrary IP SPN
  is therefore blocked.
- An unconstrained `WriteProperty` / `GenericWrite` / `GenericAll` over the target bypasses the
  validation and can place any IP SPN. That level of access comes from either administrative
  rights or an explicit delegation.

## Why this is the reassuring reading

The practical consequence is the important part. The scenario that would make IP SPN dangerous
in the trivial case, a low-privilege user spinning up a throwaway computer account and claiming
an arbitrary `host/<attacker-chosen-IP>` on it, does not work. The Validated-Write host-match
stops it. To register an arbitrary IP SPN, a principal needs full write over the target's SPN
attribute, and that is a pre-existing, well-understood dangerous permission: unconstrained write
(`GenericWrite`, `GenericAll`, or `WriteProperty` on `servicePrincipalName`) over a computer
object. It is the same class of ACL edge that already enables resource-based constrained
delegation and shadow-credential attacks, and that tools like BloodHound already flag as
high-value.

In other words, IP SPN does not introduce a new low-privilege primitive for placing service
identities. It is only reachable from an access level an attacker would already be escalating
through, and defenders already have reason to audit for. That is a meaningful containment, and
it is the sort of precise permission boundary that is worth stating explicitly, because the
misleading syntax error makes it easy to conclude either too much ("AD blocks IP SPNs entirely")
or too little ("anyone can register these") if you stop at the first result.

## Where this leaves us

Two parts in, the mechanism is fully characterized: Kerberos to an IP works, gated on an SPN
existing, and registering that SPN for an arbitrary address requires unconstrained write over
the target account rather than the constrained self-write every machine holds. Both of those are
things a defender can reason about with existing concepts.

The later parts of this series move from "how the feature works" to "how it behaves under
adversarial conditions," specifically what happens when a machine is induced to authenticate to
an IP that carries an SPN, what that authentication does and does not expose, and why enforced
signing and channel binding remain the controls that matter. Those parts are written at the
behavioral level and were prepared with coordinated disclosure in mind, so they describe what
was observed and what it means for defenders without serving as a step-by-step reproduction.

---

*This series documents original lab research conducted in an isolated environment, and is
educational and defensive in intent.*
