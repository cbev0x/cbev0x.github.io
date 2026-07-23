---
title: "What Windows Server 2025 Full PAC Validation Actually Checks"
date: 2026-07-23
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, PAC, Research]
published: true
---

## The question

The PAC has been the subject of a long series of hardening changes. The 2021 work bound the client name and SID to close the CVE-2021-42287 impersonation path. The 2024 signature CVEs, CVE-2024-26248 and CVE-2024-29056, tightened signature handling, and their enforcement has been fully on by default since April 2025, with the older compatibility modes removed. All of that answers a question about signatures. It does not answer the question I care about: what happens to a PAC whose *contents* are wrong but whose signatures are valid?

That gap is where a real vulnerability would live. If a domain controller trusts a field because it is signed, without checking the field against the account it describes, then an attacker who can produce a valid signature can assert anything that field controls. I hold a service key in the lab, so I can produce a valid server signature. The question is whether that is ever enough. I used `PACMutator` and a full-validation oracle, a plain domain-user service with no `SeTcbPrivilege` that forces the domain-controller round trip, to answer it field by field on a single-domain Windows Server 2025 lab. This post is the map.

There are two surfaces to test separately: the signatures themselves, and the content the signatures protect.

## The signature surface holds

I took a legitimately issued service ticket and, one state at a time, broke or removed each krbtgt-keyed signature: the KDC signature, the ticket signature, and the extended-KDC signature. In each state I recomputed the server signature so that it was never the reason for a rejection, isolating the krbtgt signature under test. Every state was rejected under full validation.

That is the expected result, and it is worth stating the mechanism precisely rather than just reporting it. Because I do not hold krbtgt, I cannot forge a valid krbtgt signature, and I cannot recompute one after a change either. So any edit to signed content leaves at least one krbtgt signature stale, and the domain controller catches the mismatch. This is also why the classic RID-swap-to-Administrator dies here: changing the RID in `LOGON_INFO` invalidates the KDC signature, and there is no way to repair it without the krbtgt key. The signature chain is doing exactly what it was designed to do.

There is a second, earlier line of defense worth recording. Mutations that corrupt the buffer table itself, by pushing a buffer's declared offset or size past the end of the PAC, are rejected before validation even runs, with an invalid-token error rather than a logon denial. So rejection happens in two distinct stages, and the stage tells you what went wrong.

![](/assets/img/2026-07-23-PAC_Research/3.png)

## The content surface is reconciled, not just signed

The interesting question is the content. The extended-KDC signature covers the whole PAC, so nothing is literally unsigned, and a naive reading would stop there and conclude the content is safe. But coverage is not the same as reconciliation. A field can be perfectly signed and still be a lie, if the validator trusts it rather than checking it against an authoritative source. So I went looking for fields that are signed but not cross-checked: places where the same identity is asserted twice and only one copy is checked, or where a value is carried downstream without ever being verified against the account it names.

For each candidate, the method is the same. I mutate the one field, recompute the server signature, and leave every krbtgt signature genuinely valid. Because the mutation rides inside a fully valid signature chain, it does not die at the signature wall. It reaches the consumption logic, which is exactly where a trust gap would be. Then the pair of verdicts tells me whether the field is reconciled.

I tested three.

The first was the UPN_DNS_INFO SID. When the name-and-SID flag is set, this buffer carries an independent copy of the user's SID, entirely separate from the UserId in `LOGON_INFO`. This is a genuine second assertion of identity, added to the PAC after the 2021 hardening, and a plausible place for a validation path to read one copy while trusting the other. I changed only that copy's RID, from the real user to 500, and left `LOGON_INFO` untouched. Full validation rejected it. The two SIDs are reconciled against each other.

The second was PrimaryGroupId. I changed the signed primary group from Domain Users to Domain Admins while leaving the user's actual group membership unchanged. If the domain controller honored the signed claim, that would be a privilege escalation with an intact signature chain. It rejected. The group claim is checked against real membership, not trusted because it carries a valid signature.

The third was the UPN string, and this was my best guess for a field that might be carried without checking. A UPN is often propagated verbatim to downstream systems for routing and identity, so it seemed the likeliest candidate to be trusted rather than verified. I rewrote the UPN to name a different principal while leaving the SID and SAM name as the real user, creating a deliberate mismatch between the UPN string and the identity beside it. Full validation rejected it too. The UPN string is reconciled against identity.

Four independent mutations across the signature and content surfaces, four rejections. The pattern is consistent and, honestly, decisive: Windows Server 2025 full validation treats the PAC as a set of claims to verify against ground truth, not as data to trust because it carries a valid signature. On a single domain controller, in a single domain, I found no field that is honored without reconciliation.

## The ticket-signature memory quirk

One behavior does not fit the clean logon-denied pattern, and it is worth documenting even though it turned out to be benign, because chasing it down is a good illustration of what the tool is for. When the ticket-signature buffer is absent, or present but with its size field set to zero, full validation returns an insufficient-memory error rather than the logon denial every other malformed signature produces. Removing the equally sized KDC or extended-KDC buffer does not do this, so the behavior is specific to the ticket-signature slot, which is what made it worth chasing.

I ran it down with a small matrix of states. It is not a buffer-count or table-walk artifact, because the container writes a correct count either way and correcting the count by hand changes nothing. It reproduces whether the buffer is fully removed or merely declared zero-length, so the trigger is the validator receiving no usable ticket-signature bytes, reachable two ways. And claiming an *oversized* length instead of a zero one produces a different result: it is caught earlier by the buffer-table bounds check, and the error does not vary with the claimed value, whether I ask for four kilobytes or four gigabytes. That last test is the one that matters, because a length that steered an allocation would behave differently at different magnitudes, and this one does not. It reads as a clumsy empty-input guard on the ticket-signature verify path surfacing as a memory error, not a client-controllable primitive. A quirk for the map, not a vulnerability.

## What this means

This is a null result for a vulnerability and a positive result for a map. The post-2021 hardening did its job thoroughly on the single-domain surface: every identity and authorization field I could reach is reconciled, and the signature chain is enforced end to end, in two stages, with the earlier stage catching malformed framing before validation even begins. That is worth publishing at this granularity because nobody has laid it out field by field, and because a validator that checks everything is exactly the baseline any future work needs to start from. Knowing precisely where the wall is makes it obvious where to push next.

Where the surface is not yet mapped is across a trust. Cross-domain PAC handling is a different validation path, one where a domain controller has to decide which SIDs from a foreign domain's PAC to honor and which to filter, and the trust boundary is historically where privilege-boundary bugs live. Everything in this post assumed one domain and one domain controller reconciling a PAC against its own directory. Across a trust, the reconciling authority is not the issuing one, and that gap is where I am pointing `PACMutator` next.
