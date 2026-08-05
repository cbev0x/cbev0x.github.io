---
title: "LocalKDC: A Kerberos KDC Inside Every Windows Machine"
date: 2026-08-05
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, NTLM, PKINIT, Research]
published: true
---

## The gap LocalKDC fills

Kerberos needs a KDC, and local accounts never had one. A SAM account on a standalone box, a workgroup machine, or a local account on a domain-joined host has no domain controller that will issue it tickets. So local authentication has always dropped to NTLM. There was no other option.

LocalKDC closes that last common reason for NTLM to exist. It gives local accounts a Kerberos path where before there was only the fallback.

## What it is

LocalKDC is a minimal Key Distribution Center hosted inside the Local Security Authority process on the machine itself. It is not a service you deploy on a server. It runs on the endpoint.

When a local authentication request arrives and there is no domain DC available and no IAKerb conduit to reach one, LSA consults LocalKDC instead of falling back to NTLM. The machine becomes its own tiny Kerberos authority for its own local principals.

## Where it sits in the fallback chain

LocalKDC is one branch of a decision LSA makes when it authenticates. The machine tries domain Kerberos first. If it cannot reach a domain controller directly, IAKerb can carry the exchange through a relay. If neither applies, because the account is local and there is no domain in the picture at all, LSA turns to LocalKDC. NTLM used to sit at the bottom of that chain as the catch-all. LocalKDC is what displaces it for local accounts.

Seen that way, IAKerb and LocalKDC are siblings. One keeps domain Kerberos working when the path to the DC is broken, and the other gives local identity a Kerberos authority of its own. Between them they remove the two situations that most often forced the fallback.

![](/assets/img/2026-08-05-LocalKDC_Research/localkdc_lsa_fallback_chain.png)

## What it is not

The scope is deliberately narrow, and the boundaries matter more than the feature itself.

LocalKDC does not replicate with Active Directory. It does not issue Ticket Granting Tickets for a domain. It only serves service principals that are registered locally on that machine. It is a self-contained authority for local identity, and nothing about it reaches into the domain.

## The keys

This is the part I find most interesting. The service tickets LocalKDC issues are signed with a machine-specific local keypair, and that keypair is regenerated on every reboot. No secrets are persisted across sessions. The design is aimed at low-trust local scenarios, and the key handling reflects that.

The reboot-scoped key is worth sitting with. Anything that depends on the signing key, including any attempt to forge a ticket the local KDC would accept, is bound to the key that exists for the current boot. The key does not survive a restart, which changes the shape of both forgery and persistence compared to a domain KDC whose long-term keys live in the directory.

The local keypair also gives the whole thing a certificate flavor, closer to PKINIT than to a shared-secret KDC. That is the angle I expect to pull on hardest, since certificate and key handling is where I already spend my time.

## A different key model

It is worth putting this key handling next to a domain KDC to see how different it is. A domain KDC signs with the krbtgt key, a long-term secret that lives in the directory, replicates between controllers, and survives reboots. Compromising it offline is the entire premise of a golden ticket. LocalKDC has no such anchor. Its signing key is generated locally, held by LSA, and discarded at the next boot.

That is a deliberate low-trust posture. There is no durable secret sitting on disk for an attacker to lift and reuse offline, and a ticket only means anything within the boot session that produced it. The tradeoff is that the trust is shallow on purpose, which is appropriate for local accounts on a single machine but is also why this surface is going to behave differently from anything domain-side I am used to reasoning about.

## Telemetry

LocalKDC ships with its own event channel, `Microsoft-Windows-LocalKDC/Operational`. If you go looking for its activity, that is the channel to watch. Note that it is a distinct name from the general Kerberos operational channel, which is easy to miss if you probe for the wrong provider.

## Where it stands today

LocalKDC arrived in the June 2026 Insider preview alongside IAKerb, but unlike IAKerb it is disabled by default in that preview. It is controlled by a registry value for now, with Group Policy and MDM management planned as the feature matures. General availability is targeted for the second half of 2026 on Windows 11 24H2 and Windows Server 2025.

## How much NTLM this removes

I want to be precise about scope, because it is easy to read the NTLM headlines and overstate it. LocalKDC removes the local-account reason for NTLM fallback, and IAKerb removes the no-path-to-a-DC reason. Those are the two big ones. They are not all of it. Applications and components with NTLM hardcoded into them, and legacy devices that only speak NTLM, are a separate cleanup that these two features do not touch. LocalKDC closes a specific and very common door. It does not by itself end NTLM.

## Why I am looking at this

A KDC running inside LSA on every machine is a brand new local target, and nobody has characterized its offensive surface yet. The questions I want answered are basic and unanswered. What does a LocalKDC ticket actually look like on the wire, and does it carry a PAC at all. How is the ephemeral keypair generated and protected within LSA. What counts as a locally registered service principal, and what does local-account Kerberos let you reach that NTLM did not. What the reboot-scoped signing key does to persistence.

There is no Unix analog to diff this against, so unlike IAKerb I cannot build a cross-implementation baseline yet. For now this is spec work and a standalone KDC reference model, and the real comparison waits for the Windows feature to be testable. This post is the primer. The characterization comes once I can capture the real thing.
