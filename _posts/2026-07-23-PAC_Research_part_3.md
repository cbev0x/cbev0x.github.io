---
title: "Cross-Forest PAC Filtering on Windows Server 2025, Field by Field"
date: 2026-07-26
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, PAC, Research]
published: true
---

## What I tested

When a principal from a trusted forest authenticates to a resource in a trusting forest, the trusting KDC applies SID filtering to the PAC while it issues the service ticket. The rules live in [MS-PAC] section 4.1.2.2, but the field-level behavior under current Server 2025 enforcement is not something I found characterized anywhere. I wanted the empirical map: which SIDs survive the filter, which get stripped, and which get the whole ticket rejected. So I changed one PAC field at a time, pushed each through a real forest trust, and read what came back.

The tool is PACMutator, my field-level PAC mutation instrument. It does not forge a ticket from scratch the way ticketer-style tools do. It takes a legitimately issued ticket, mutates one buffer or field, reseals it while preserving everything else, and lets me observe the validator. For this phase the mutated artifact is the cross-realm referral TGT, and the validator is the trusting DC.

## The lab

Two Server 2025 forests, `reflect.lab` (the trusting and resource side) and `trust.lab` (the trusted side), joined by a two-way forest trust at default settings. The test principal is an ordinary user in `trust.lab`. The resource is a service on a `reflect.lab` member server, running under an account without `SeTcbPrivilege` so that full PAC validation applies. I read every issued ticket with `describeTicket` to see the PAC the trusting DC actually produced.

## The method

A cross-realm request produces a referral TGT for `krbtgt/reflect.lab@trust.lab`. That ticket is the artifact the trusting KDC filters, so it is the artifact I mutate. I decrypt it with the inter-realm trust key, rewrite one field, recompute the server signature with that same trust key, and reseal. I then present the mutated referral TGT to the trusting DC in a TGS request and capture the service ticket it issues.

Two mechanics are worth stating because they are easy to get wrong. First, the referral TGT is keyed with the trusted forest's outbound inter-realm key, and the usable form of that key comes from `lsadump::trust /patch`, not from a per-account secrets dump, because the cross-realm salt differs. Second, the trusting DC verifies only the server signature on the inbound referral TGT. It has no copy of the foreign krbtgt, so it cannot and does not verify the KDC, ticket, or extended-KDC signatures on that ticket. I confirmed this directly: an unmutated ticket resealed with its foreign signatures left stale still issues normally, so those signatures are not part of the inbound decision.

## What the filter does

I ran four probes. Each changed exactly one thing, and each was verified to be well-formed before delivery so that a rejection would reflect the filter, not a malformed splice.

First, I made the trusted-forest ticket assert the trusting forest's own domain SID, keeping the user's RID so that the PAC claimed to be a specific `reflect.lab` account. The DC returned `KDC_ERR_POLICY` at the TGS stage. This is a hard reject, and I isolated it to the SID filter by rewriting the domain SID in both `LOGON_INFO` and `UPN_DNS` so the PAC was internally consistent. The reject persisted, which rules out the internal cross-check and leaves the filter as the cause.

Second, I injected a `reflect.lab` high-privilege SID (Domain Admins) into the ExtraSids array. The DC issued the ticket, but the re-issued PAC came back with that SID removed. This is a soft strip. The foreign SID is silently dropped and the ticket still succeeds.

Third, I injected the trusted forest's own Enterprise Admins SID, a RID below 1000, into ExtraSids. This one survived into the issued ticket, and it survived under both default filtering and with SID history enabled. The survival is expected. The trusted forest is authoritative for its own domain, so the filter has no reason to drop a SID that genuinely belongs to it.

Fourth, I injected the universal built-in SIDs, starting with `S-1-5-32-544` (Administrators) and then sweeping the other privileged built-ins: Account, Server, Print, and Backup Operators, and Enterprise Domain Controllers (`S-1-5-9`). None of these are domain-relative. They are the same values on every Windows system. The DC stripped all of them.

## The model

Two rules explain every result. The filter is namespace-based: it passes SIDs that belong to the trusted forest's own namespaces and strips SIDs that belong to a foreign namespace. On top of that sits an always-filter set that removes universal, non-domain-relative SIDs like the built-in groups regardless of where the ticket came from, and that set is complete for the privileged built-ins I tested. The domain SID assertion is a third case, a claim to be the trusting forest itself, which the KDC refuses outright rather than sanitizing.

The one variable that did not move any result was the SID history toggle. Both the foreign SID and the trusted-forest SID behaved identically with it on and off. That is because the toggle governs a different category, migrated SIDs belonging to a domain the trusted forest absorbed, which is a case my two-forest lab cannot produce.

## Why none of this is a privilege escalation

The interesting part is what the two rules do together. The SIDs that survive the filter are the trusted forest's own, and the resource forest does not privilege them. Enterprise Admins in `trust.lab` is a different SID from Enterprise Admins in `reflect.lab`, so carrying the former into a `reflect.lab` ticket puts an unprivileged foreign group into the token and nothing more. The SIDs the resource forest would actually honor, its own high-privilege groups and the universal built-ins, are exactly the ones the filter strips or rejects. A surviving SID is inert and a privileged SID does not survive. Both halves are closed.

## The SID history point

A common belief is that enabling SID history on a forest trust opens the door to injecting the resource forest's privileged SIDs across the boundary. On default Server 2025 that did not hold in my testing. A `reflect.lab` Domain Admins SID injected into a `trust.lab` ticket was stripped whether SID history was enabled or not, because it is foreign to the trusted forest's namespace and namespace filtering runs regardless of the toggle. Enabling SID history relaxes the handling of the trusted forest's own historical SIDs, not the handling of the resource forest's SIDs.

## Scope and limits

This characterizes a single default forest trust between two single-domain forests on Server 2025. I did not test a trusted forest that had absorbed another domain via migration, which is the one configuration where the SID history toggle actually changes behavior, and I call that out as future work rather than implying the toggle is inert. Quarantine as a trust attribute is not applicable to a forest trust and would need an external trust to exercise. As always, the results are from a controlled lab and describe behavior, not a defect.

## Takeaways

For defenders, the default forest trust filter on Server 2025 behaves the way the documentation implies it should, and the SID history worry does not translate into foreign privileged-SID injection on its own. For researchers, the value here is the method: a field-level differential that reaches the filter with one variable changed at a time, which is what let me separate the namespace rule from the always-filter set from the internal consistency check, three mechanisms that otherwise blur into a single "rejected." The tool and the full matrix will be in the repo.
