---
title: "Forging a Device Claim to Beat a Tier-0 Silo"
date: 2026-08-03
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Claims, DAC, Silos, Research]
published: false
---

## How claims and silos work

A claim is an assertion about an identity that a KDC issues and a resource can act on. In Active Directory a claim type is defined centrally and sourced from an attribute: a UserCity claim reads the `l` attribute, a device DeviceDescription claim reads `description` on a computer object. When the KDC issues a ticket, it reads the source attribute, resolves the claim, and packs it into the ticket. User claims describe the account; device claims describe the machine the account is authenticating from.

Claims ride in the PAC inside the ticket, in dedicated buffers: buffer 13 (`CLIENT_CLAIMS_INFO`) for user claims and buffer 14 (`DEVICE_CLAIMS_INFO`) for device claims. Device claims only reach the KDC when the request is armored, because the armor TGT is what carries the device's identity into the exchange. That is the dependency to keep in mind: no armor, no device claim. I cover the armor mechanism itself in my write-up on Kerberos FAST armoring and enforcement.

An authentication policy silo restricts how and from where its member accounts can authenticate. The relevant control is the `AllowedToAuthenticateFrom` condition, an SDDL conditional ACE, and it can gate on a device in two very different ways:

- **Device group membership.** The condition requires the device to be a member of a group, for example a Privileged Access Workstation group. A low-privilege user cannot add a device to a protected group, so this pattern is safe.
- **A device claim sourced from an attribute.** The condition requires a device claim to hold a value, for example `DeviceDescription == "PAW"`. The decision now trusts whatever that attribute contains, so the safety of the silo depends on who can write the attribute.

Those two conditions can look identical in an admin's mind and nearly identical in tooling. One is safe. The other trusts data. For the conditional ACE to gate on a claim at all, it has to reference the claim by its full resolved identifier, not a friendly name; a bare name evaluates as always-deny, and the device's own claim is evaluated in the `@USER` namespace of the armor token.

## The setup an admin builds

Take a domain with Dynamic Access Control and Kerberos Armoring turned on. An admin defines a device claim, DeviceDescription, sourced from the `description` attribute of computer objects. They build a Tier-0 authentication policy silo whose `AllowedToAuthenticateFrom` condition requires the authenticating device to assert `DeviceDescription == "PAW"`, the intent being that Tier-0 accounts can only log on from a privileged access workstation. On paper this is a device-gated silo, the modern way to protect Tier-0.

The problem is that the condition trusts an attribute, and the attribute is writable by an account I can create with no privileges.

## The primitive

Starting as an ordinary low-privilege user, `jdoe`, with nothing but a domain account:

1. **Mint a machine.** The default Machine Account Quota lets any authenticated user create a computer account. I create `evilpc$`. Because I set its password, I control it and can authenticate as the machine.

2. **Self-write the claim source.** Authenticating as `evilpc$`, the machine's own SELF principal holds the Personal-Information property set by default, which covers `description` along with the whole location and cloud-extension family of attributes. I write `description = PAW` on `evilpc$`.

3. **Armor with it.** I obtain `evilpc$`'s TGT and use it as the FAST armor for a Tier-0 account's request. The device claim DeviceDescription resolves from `description`, reads `PAW`, and the silo condition is satisfied.

4. **Result.** The KDC issues the Tier-0 TGT. I have satisfied a device-claim condition guarding Tier-0 with an account I created and an attribute I wrote, holding zero administrative rights.

## The control

The finding is only real if the value is what flips it. With `description = PAW` the Tier-0 TGT issues. I self-write `description = NOTPAW`, re-mint, and the KDC returns `KDC_ERR_POLICY`. Revert to `PAW` and it issues again. The bypass tracks the attribute value exactly.

The safe sibling confirms the boundary: if the silo condition had gated on device group membership instead of a device claim, `jdoe` could not have satisfied it, because a low-privilege user cannot add a machine to a protected group.

## It is a class, not a one-off

The same shape works on the user axis. A DAC-protected file share whose conditional ACE gates on a user claim sourced from a self-writable user attribute (`l`, `postalCode`, any of the twenty `msDS-cloudExtensionAttribute` values, and others) falls the same way: `jdoe` writes the value, the claim resolves, access is granted, and self-writing a non-matching value revokes it. Two axes, one class: control a principal (a machine I mint, or my own user), find an authorization decision that trusts a claim sourced from an attribute that principal can write, forge the value, and satisfy the decision.

The precondition that matters is not the Machine Account Quota, which is only the zero-privilege way to acquire a machine. It is control of any machine account, because the machine SELF write set is broad, and that broad write set is the same self-writable family as the user sibling.

## Honest scope

This is not an arbitrary, default-config escalation, and I want to be precise about that. It requires the admin to have configured all of the following: claims and armoring enabled, a device (or user) claim type sourced from a self-writable attribute, and an authorization decision that gates on that claim. Out of the box there are no claim types and no claim-gated silos, so all three are deliberate. The common and safe device-gated silo pattern is group membership, which no attacker-writable attribute touches.

What pushes this past "misconfiguration" is the false equivalence. The entire location, office, geo-coordinate, and cloud-extension attribute set is self-writable, and those are exactly the attributes an admin would naturally pick as a device or user property to source a claim from. The configuration surface gives no writability warning, and a claim-based condition looks the same as the safe group-based one. An admin choosing a claim source is not being careless; they are stepping into a trap the tooling does not flag.

## What to check

- Audit every claim type for whether its source attribute is writable by the principals the claim describes. For device claims, that means the computer SELF write set. For user claims, the user's own self-writable attributes.
- Prefer device group membership over device claims for silo conditions guarding Tier-0.
- Treat the `msDS-cloudExtensionAttribute1..20` set with particular suspicion. It is self-writable by design, opaque, and its writability is not widely known.
- Set the Machine Account Quota to zero. It does not close the class, but it removes the zero-privilege machine-acquisition path.

## Status

Reported to MSRC. This post publishes after coordinated disclosure. The durable contribution regardless of disposition is the class: an authorization decision that trusts a claim is only as trustworthy as the writability of the attribute behind it.
