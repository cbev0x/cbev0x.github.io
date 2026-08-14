---
title: "Authentication Policy Device Revocation Bypass via Stale Kerberos FAST Armor"
date: 2026-08-13
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, FAST, Research]
published: false
---

## Executive Summary

Active Directory Authentication Policies can restrict sensitive accounts so they are only permitted to authenticate from explicitly authorized devices. In environments using Kerberos FAST and device-based restrictions, the Key Distribution Center evaluates authorization information associated with the computer TGT used as FAST armor. During testing, I found that revoking a device in Active Directory does not necessarily cause that device to immediately stop satisfying an enforced Authentication Policy. If a machine TGT was issued while the device satisfied the policy, the authorization information represented by that ticket can continue to be used after the device's live directory state changes. A protected user can therefore obtain completely fresh Kerberos TGTs from a workstation that no longer satisfies the Authentication Policy, as long as the workstation continues using a machine TGT issued while it was still authorized.

The issue is not limited to a single type of restriction. I reproduced the behavior with both group-based and claim-based device conditions. I also reproduced it at both the user AS stage and the service TGS stage, including compound-authentication scenarios where a service-side Authentication Policy evaluated device information carried through FAST armor. The behavior also survives a domain controller boundary. A machine TGT issued by one KDC while the workstation was authorized continued to satisfy an Authentication Policy enforced by another KDC after that second domain controller had already replicated the workstation's revoked state. This ruled out a simple per-DC cache explanation and strongly indicated that the stale authorization was traveling with the machine ticket itself.

Normal machine-TGT renewal extended the stale authorization condition. A pre-revocation machine TGT could be renewed after the device had been revoked, and the renewed ticket continued permitting completely fresh protected-user authentication without requiring a fresh machine AS exchange. I also tested several revocation and containment paths. Changing the underlying group or claim did not invalidate existing armor. Resetting the machine account password did not invalidate the ticket or stop renewal. Disabling the computer account prevented future machine authentication and renewal but did not immediately invalidate already-issued armor in an active session. Deleting the computer account provided a hard cutoff in the tested compound-authentication path. Rebooting the workstation also ended the stale condition because the machine subsequently obtained a fresh TGT containing current device authorization.

A separate mitigation test showed that assigning the workstation a short-lived Computer Authentication Policy materially changed the native ticket lifecycle. Although Windows Server 2025 accepted explicit renewal requests for those machine TGTs, native Windows ticket maintenance did not renew them in the same way. As the short-lived ticket approached expiration, Windows performed a fresh machine AS exchange and incorporated the current revoked device state. The end result is a revocation gap. The policy decision is based on authorization represented by an already-issued machine TGT, while administrators may reasonably expect a change to the device's live Active Directory state to immediately affect future protected-user authentication.

---

## Background

### Authentication Policies

Active Directory Authentication Policies provide additional controls over how sensitive users, computers, managed service accounts, and related security principals may authenticate. One of the more interesting capabilities is the ability to restrict where a protected user is allowed to authenticate. A policy can apply an access-control expression through `msDS-UserAllowedToAuthenticateFrom` and use device information as part of that decision. This is useful for high-value accounts. A privileged account can, for example, be restricted so it only authenticates from a designated administrative workstation.

At a high level, the expected security property is simple:

> If a workstation no longer satisfies the restriction protecting a privileged account, that workstation should no longer be able to obtain new authentication material for that account.

The interesting part is how the KDC determines whether the workstation satisfies that restriction.

### Kerberos FAST and Machine Armor

Windows uses Kerberos FAST, commonly referred to as Kerberos armoring, to protect portions of the Kerberos authentication exchange. In a domain environment, the computer's TGT can act as the armor credential for subsequent user authentication. This gives the KDC a device identity and authorization context while processing the user's request.

That creates two separate sources of device state:

1. The computer object's current state in Active Directory.
2. The authorization information represented by an already-issued machine TGT.

My testing focused on what happens when those two sources stop agreeing.

---

## Lab Environment

All testing was performed in an isolated Active Directory lab.

The primary systems were:

- Domain: `REFLECT.LAB`
- `DC01.reflect.lab`: Windows Server 2025 domain controller
- `DC03.reflect.lab`: second Windows Server 2025 domain controller
- `WS01.reflect.lab`: Windows 11 25H2 workstation
- `ap_user`: protected Authentication Policy test user
- `ap_tgs_user`: user used for service-ticket policy testing
- `ap_tgs_svc`: service account used for TGS-stage Authentication Policy testing

Kerberos FAST and compound authentication were enabled throughout the environment.

The main claim-based Authentication Policy used for the AS-stage tests was named:

`AP-Claim-Only`

The relevant device claim was sourced from the workstation's `department` attribute.

Authorized state:

`department = AP-Allowed`

Revoked state:

`department = AP-Revoked`

The policy expression required the device claim to equal `AP-Allowed`.

For TGS-stage testing, I used a separate service Authentication Policy named:

`AP-TGS-Device-Claim`

The service account `ap_tgs_svc` owned the SPN:

`aptest/srv01.reflect.lab`

The service policy also required the device claim to equal `AP-Allowed`.

---

## The Core Behavior

The simplest reproduction started with WS01 in an authorized state.

I set:

`WS01.department = AP-Allowed`

I then purged the SYSTEM Kerberos cache and obtained a fresh machine TGT. At this point, the machine TGT was issued while the workstation satisfied the Authentication Policy's device requirement.

Without purging or replacing that machine TGT, I changed the live directory state of WS01 to:

`WS01.department = AP-Revoked`

The important point is that the workstation was now revoked in Active Directory, but it still held the machine TGT issued while it was allowed. I then performed a completely fresh logon as `ap_user`. The logon succeeded. The KDC issued a new TGT for the protected user even though the workstation no longer satisfied the policy according to its current Active Directory state. I then purged the machine TGT and forced WS01 to obtain a genuinely fresh machine TGT while `department = AP-Revoked`. The exact same `ap_user` authentication then failed with `KDC_ERR_POLICY`, and the corresponding Authentication Policy failure event identified `WS01$` as the device that failed the restriction.

This produced a clean two-cell comparison:

| Machine armor state | Live WS01 state | Protected user result |
|---|---|---|
| TGT issued while `AP-Allowed` | `AP-Revoked` | ALLOW |
| Fresh TGT issued while `AP-Revoked` | `AP-Revoked` | DENY |

The live directory state was identical in both cases. The difference was the generation of the machine TGT used as FAST armor.

---

## Full Stale vs Fresh Authorization Matrix

Before moving into renewal behavior, I tested the same idea as a four-cell matrix using a group-based device condition.

The results were:

| Live device membership | Machine TGT authorization | Result |
|---|---|---|
| Removed | Fresh removed state | DENY |
| Added | Stale removed state | DENY |
| Added | Fresh allowed state | ALLOW |
| Removed | Stale allowed state | ALLOW |

This was useful because it showed that the policy decision followed the authorization represented by the machine ticket rather than the live group membership. I later repeated the same concept using a device claim instead of group membership and observed the same result. That ruled out a group-specific implementation detail.

---

## Claim-Based Restrictions Behave the Same Way

The claim-based test used the `department` attribute as the source for a device claim.

The sequence was:

1. Set WS01 to `AP-Allowed`.
2. Obtain a fresh machine TGT.
3. Change WS01 to `AP-Revoked`.
4. Keep the existing machine TGT.
5. Authenticate as the protected user.

The protected user continued authenticating successfully. After purging the machine TGT and obtaining a fresh ticket while WS01 was revoked, the protected-user authentication failed with an Authentication Policy denial. This confirmed that the stale-authorization condition is not limited to group membership. Device claims represented in the machine authorization context are affected as well.

---

## Existing User TGTs Are Not the Interesting Part

An already-issued user TGT remaining valid after a device is revoked is not particularly surprising on its own. I tested this separately to make sure I was not confusing two different behaviors. A user TGT obtained while the workstation was authorized remained usable for later TGS requests after the device was revoked. That is expected ticket-lifetime behavior. The more significant issue is that the stale machine TGT can be used to obtain a completely new protected-user TGT after revocation.

The distinction matters:

`Existing protected-user ticket remains valid`

is different from:

`Revoked device can continue obtaining new protected-user tickets`

The second case is the one this research focuses on.

---

## Machine TGT Renewal Extends the Stale Authorization

The next question was whether the stale authorization would disappear when the machine TGT was renewed. It did not. Using the native Windows Kerberos cache, I renewed the machine TGT after changing the workstation from `AP-Allowed` to `AP-Revoked`. The domain controller recorded Event 4770 for the machine ticket renewal. There was no corresponding fresh machine Event 4768 in the same renewal path. After renewal, I performed another completely fresh authentication as the protected user. The authentication succeeded. This means the stale authorization did not simply survive until the original machine TGT expired. It survived a Kerberos renewal operation and continued satisfying the enforced Authentication Policy afterward. In testing, native Windows also performed unattended renewal of a normal machine TGT while the live device state was already revoked. The renewed ticket continued permitting fresh protected-user authentication. This materially changes the revocation window.

Without renewal, the stale condition could be described as lasting for the remaining lifetime of the original machine ticket. With renewal, the stale authorization can survive normal ticket maintenance without requiring a fresh machine AS exchange.

---

## RenewUntil Is the Hard Boundary for the Normal Machine TGT Lineage

I also tested what happened when the original renewable ticket lineage reached its `RenewUntil` boundary. Once the machine ticket could no longer be renewed, Windows had to perform a fresh machine AS exchange. At that point, the KDC incorporated the workstation's current revoked state. The protected-user authentication then failed.

This produced a useful lifecycle model:

```text
Machine TGT issued while device is allowed
        |
        v
Device revoked in Active Directory
        |
        v
Existing machine TGT continues satisfying policy
        |
        v
Machine TGT renewal preserves stale authorization
        |
        v
Additional protected-user TGTs can still be issued
        |
        v
Original renewable lineage reaches RenewUntil
        |
        v
Fresh machine AS exchange
        |
        v
Current revoked state is incorporated
        |
        v
Protected-user authentication denied
```

---

## TGS-Stage Authentication Policies Are Also Affected

I wanted to know whether the issue only affected `AllowedToAuthenticateFrom` checks during the AS exchange or whether stale machine authorization could also affect service-side policy decisions.

To test this, I configured:

- `ap_tgs_user` as the client user
- `ap_tgs_svc` as the target service account
- `aptest/srv01.reflect.lab` as the SPN
- `AP-TGS-Device-Claim` as the service Authentication Policy

The service policy required the device claim:

`APDeviceState == "AP-Allowed"`

With WS01 authorized, I obtained a fresh machine TGT and confirmed that the FAST compound TGS request succeeded. I then changed WS01 to `AP-Revoked` without replacing the machine TGT. The same FAST compound TGS request still succeeded. After purging the machine TGT and obtaining a fresh one while WS01 was revoked, the service-ticket request failed with `KDC_ERR_POLICY` and Event 106.

This showed that the same stale armor authorization can influence both:

- AS-stage policy evaluation for protected-user TGT issuance
- TGS-stage policy evaluation for protected-service access

---

## One Stale Armor Context Can Satisfy Both AS and TGS Policy Gates

I then combined both policy stages. `ap_tgs_user` was assigned the claim-based AS Authentication Policy, while `ap_tgs_svc` retained the TGS-stage service Authentication Policy.

Both required:

`APDeviceState == "AP-Allowed"`

I issued a machine TGT while WS01 was allowed, then changed the workstation to `AP-Revoked`.

With the stale machine armor still present:

1. A fresh user TGT was issued successfully.
2. A fresh FAST compound service ticket was also issued successfully.

No fresh machine AS exchange occurred between the revocation and those two policy decisions. A single stale machine authorization context therefore satisfied two independent Authentication Policy gates in sequence. When I replaced the machine TGT with a fresh ticket issued while WS01 was revoked, the protected-user AS request failed and the chain stopped.

---

## Asymmetric Policy Testing

To prove that the KDC was independently evaluating the same machine armor against separate policy expressions, I temporarily made the AS and TGS policies require different device claim values.

The AS policy still required:

`AP-Allowed`

The TGS policy was changed to require:

`AP-TGS-Only`

With a machine TGT issued while WS01 carried `AP-Allowed`, the protected-user AS request succeeded but the service TGS request failed. This showed that the same armor context was not being treated as a generic "trusted workstation" flag. It was being evaluated independently against the relevant policy expression at each stage. I also tested split-generation behavior. An existing user TGT obtained while the machine armor represented `AP-Allowed` remained usable for a later TGS request after the machine TGT was replaced with a fresh generation carrying `AP-TGS-Only`. The result showed that AS and TGS authorization can be influenced by different machine-ticket generations during the same user session.

---

## Cross-KDC Validation

One of the strongest tests was designed to rule out a per-domain-controller cache explanation. I added a second healthy writable domain controller, `DC03`.

The sequence was:

1. WS01 was set to `AP-Allowed`.
2. A fresh machine TGT was obtained from DC01.
3. WS01 was changed to `AP-Revoked`.
4. The change was explicitly replicated to DC03.
5. DC03 was queried directly and confirmed to see `AP-Revoked`.
6. WS01 retained the original DC01-issued machine TGT.
7. A fresh protected-user authentication was directed to DC03.

DC03 issued the protected-user TGT successfully.

The positive case therefore looked like this:

```text
DC01 issues machine TGT while WS01 = AP-Allowed
        |
        v
WS01 changed to AP-Revoked
        |
        v
DC03 replicates and confirms AP-Revoked
        |
        v
DC01-issued machine TGT used as FAST armor against DC03
        |
        v
DC03 issues fresh protected-user TGT
```

I then performed the negative control. The stale machine TGT was purged and WS01 obtained a fresh machine TGT while the workstation remained `AP-Revoked`. A protected-user AS request was forced to DC03.

DC03 returned:

`KDC_ERR_POLICY`

This produced the clean cross-KDC pair:

| Armor source | Live state on enforcing KDC | Result |
|---|---|---|
| DC01-issued stale `AP-Allowed` machine TGT | DC03 sees `AP-Revoked` | ALLOW |
| Fresh `AP-Revoked` machine TGT | DC03 sees `AP-Revoked` | DENY |

This ruled out the idea that the successful authentication was caused by stale directory state or a local cache on the original KDC. The stale authorization was effective across a KDC boundary.

---

## Resource-Side Policy State Is Evaluated Live

The stale behavior does not mean that all Authentication Policy state is cached in tickets. I changed the TGS-stage service policy itself while keeping the client and machine ticket state unchanged. Changing the policy expression from an allowed condition to an impossible condition immediately caused the next service-ticket request to fail. Likewise, clearing the policy assignment from `ap_tgs_svc` caused the request to succeed, and reassigning the deny policy caused it to fail again. This is an important distinction. The resource-side Authentication Policy content and assignment were evaluated live. The stale state was specifically associated with the device authorization represented by the machine armor.

---

## Service Account Disable and Existing Service Tickets

I also tested the lifecycle of the target service account. Disabling `ap_tgs_svc` prevented new service-ticket issuance for its SPN.

A packet capture showed the KDC returning:

`KDC_ERR_S_PRINCIPAL_UNKNOWN`

for the service request. However, a service ticket issued before the account was disabled remained usable directly against a Kerberos acceptor. I used a .NET `NegotiateStream` listener to validate the ticket and confirmed successful Kerberos authentication after the service account had been disabled. A packet capture around the second service authentication showed no new Kerberos traffic and no communication with a domain controller. This is expected ticket-consumption behavior, but it was useful for distinguishing target-service revocation from the stale machine-armor issue.

---

## Remediation and Revocation Testing

A large part of the research focused on determining what actually terminates the stale authorization condition.

### Changing the Device Group or Claim

Changing the underlying group membership or claim value did not invalidate an already-issued machine TGT. This is the core behavior. The workstation remained able to obtain fresh protected-user authentication material until the machine armor was replaced with authorization reflecting the current state.

### Resetting the Machine Account Password

Resetting the machine account password did not invalidate the existing machine TGT. More importantly, the pre-password-reset machine TGT could still be renewed afterward. The domain controller recorded Event 4770 for the renewal, with no fresh machine AS exchange. The renewed ticket continued carrying the stale authorization behavior. A password reset only became effective for this purpose once the existing machine ticket lineage was purged and a fresh machine AS exchange occurred.

### Disabling the Computer Account

Disabling WS01 prevented future machine authentication and blocked machine-TGT renewal. The KDC returned the expected client-revoked behavior for new machine authentication attempts. However, disabling the computer account did not immediately invalidate an already-issued machine armor TGT. In an active user session, I could still obtain fresh protected-user Kerberos material using the stale armor after WS01 had been disabled. I also tested the common 20-minute client-TGT good-standing interval by aging the ticket beyond that threshold. The stale armor still remained effective in the tested protected-user flow. So disabling the computer account is useful for stopping future machine authentication and renewal, but it should not be treated as immediate invalidation of every authorization decision that can still be satisfied by an already-issued machine ticket.

### Deleting the Computer Account

Deleting the WS01 computer object produced a much stronger cutoff. With the machine object deleted, the tested compound-authentication flow stopped functioning.

Fresh machine authentication failed with:

`KDC_ERR_C_PRINCIPAL_UNKNOWN`

and the stale machine armor could no longer be used to complete the protected authentication path I was testing. After restoring the environment from snapshots, the original SID and trust relationship were restored for continued testing.

### Rebooting the Workstation

Rebooting WS01 also ended the stale authorization condition.

Before reboot:

- WS01 was live `AP-Revoked`
- the machine cache still contained an `AP-Allowed` generation TGT
- `ap_user` authentication succeeded

After a normal reboot:

- the old SYSTEM Kerberos cache was gone
- WS01 obtained a new machine TGT
- the new machine TGT was issued while WS01 was `AP-Revoked`
- `ap_user` authentication failed with Event 105 and `KDC_ERR_POLICY`

This gives defenders a practical containment boundary. A normal workstation reboot destroys the cached machine-ticket context and forces subsequent authentication to use current machine authorization.

---

## Authentication Policy Silos

I also tested whether Authentication Policy Silo membership changed the underlying behavior. The main result here was about policy selection rather than the stale-ticket issue itself.

A valid silo enforcement path required both:

- the user's `msDS-AssignedAuthNPolicySilo` link
- membership in the silo's `msDS-AuthNPolicySiloMembers`

If either half was broken, the silo policy did not apply. When the silo membership path was incomplete but a direct Authentication Policy was assigned, the direct policy applied instead. When both the silo path and direct policy were absent, no Authentication Policy applied. This behavior was useful for understanding policy precedence and avoiding false conclusions while testing, but I do not currently consider it part of the core vulnerability.

---

## Short-Lived Computer Authentication Policies

The most useful mitigation-oriented test involved assigning WS01 its own Computer Authentication Policy.

I created:

`AP-Computer-Short-TGT`

with:

`ComputerTGTLifetimeMins = 45`

The 45-minute value was the minimum accepted by the cmdlet in this environment.

After assigning the policy to WS01 and obtaining a fresh machine TGT, the resulting ticket had:

```text
StartTime   = T
EndTime     = T + 45 minutes
RenewUntil  = T + 45 minutes
```

This differed significantly from the normal machine TGT with the domain's standard longer renewable lifetime. There was one implementation detail that surprised me. The ticket was still marked `renewable`, and explicit renewal requests succeeded. Each explicit renewal advanced both `EndTime` and `RenewUntil`. So I would not describe the ticket as literally impossible to renew on this Windows Server 2025 build. However, the security behavior was different from a normal machine TGT.

When I:

1. issued the short-lived machine TGT while WS01 was `AP-Allowed`,
2. changed WS01 to `AP-Revoked`,
3. explicitly renewed the ticket,

the renewed machine armor no longer satisfied a TGS-stage policy requiring `AP-Allowed`.

A packet capture showed a FAST compound TGS request for:

`aptest/srv01.reflect.lab`

followed by:

`KDC_ERR_POLICY`

This indicates that the effective device authorization used by later policy checks was refreshed during that renewal path. I then tested native Windows ticket maintenance using a controlled time jump. I issued a fresh 45-minute machine TGT while WS01 was authorized, revoked WS01, confirmed that the stale machine ticket still allowed `ap_user` to authenticate, then advanced the clocks into the ticket's near-expiry window. Windows did not perform Event 4770 renewal. Instead, it performed a fresh machine AS exchange, recorded as Event 4768. The old machine TGT was replaced with a new 45-minute ticket issued while WS01 was already `AP-Revoked`. The next `ap_user` logon failed. This means a short Computer Authentication Policy can materially reduce the stale-authorization window under native Windows ticket maintenance. I would still treat this as a mitigation tradeoff rather than a universal recommendation. Shorter machine-ticket lifetimes increase authentication activity and should be tested carefully in the target environment.

---

## Results Summary

The following table summarizes the most important lifecycle results.

| Test | Result |
|---|---|
| Remove device from allowed group, keep old allowed machine TGT | ALLOW |
| Change device claim to revoked, keep old allowed machine TGT | ALLOW |
| Fresh machine TGT after revocation | DENY |
| Existing protected-user TGT after device revocation | Remains usable |
| Renew normal stale machine TGT after revocation | Stale authorization persists |
| Native unattended renewal of normal stale machine TGT | Stale authorization persists |
| Reach normal machine TGT `RenewUntil` boundary | Fresh machine AS, then DENY |
| TGS-stage device policy with stale allowed armor | ALLOW |
| TGS-stage device policy with fresh revoked armor | DENY |
| Same stale armor through AS and TGS policy gates | ALLOW at both stages |
| Cross-KDC stale armor, enforcing DC has current revoked state | ALLOW |
| Cross-KDC fresh revoked armor | DENY |
| Change resource-side service policy live | Immediately enforced |
| Remove service Authentication Policy assignment | Immediately stops enforcement |
| Disable target service account | Prevents new TGS issuance |
| Already-issued service ticket after service disable | Still usable |
| Reset machine password | Existing stale armor remains valid |
| Renew pre-password-reset machine TGT | Renewal succeeds |
| Disable workstation computer account | Stops future machine auth/renewal, but cached armor can remain usable |
| Delete workstation computer account | Hard cutoff in tested compound path |
| Reboot workstation | Fresh machine TGT, stale condition ends |
| 45-minute Computer Authentication Policy TGT | Short lifetime, native near-expiry path performs fresh AS |
| Explicit renewal of 45-minute computer-policy TGT | Renewal accepted, effective device authorization refreshed |

---

## Security Impact

The practical impact depends on how Authentication Policies are being used. The most relevant case is a protected or privileged user whose ability to authenticate is intentionally restricted to a trusted workstation.

An administrator may revoke that workstation by:

- removing it from an allowed group,
- changing an attribute used by a device claim,
- or otherwise making the computer no longer satisfy the Authentication Policy.

The live Active Directory object now reflects that the device is not trusted. However, if the workstation still possesses a machine TGT issued while it was trusted, that existing authorization context can continue satisfying the device restriction. A fresh protected-user TGT can therefore still be issued after the administrator has revoked the device. Normal machine-TGT renewal can further extend that condition without requiring fresh machine authentication. The important security distinction is that this is not merely continued use of authentication material issued before revocation. It is the issuance of new protected-user authentication material after revocation, based on stale device authorization carried through the Kerberos armor context.

---

## Defensive Considerations

Based on the testing, changing the device's group membership or claim value should not be treated as immediate revocation of all Authentication Policy authorization derived from an existing machine TGT. For high-risk containment, defenders should consider actions that force the machine to lose or replace the existing Kerberos armor context. A workstation reboot was effective in testing because it removed the old SYSTEM Kerberos cache and caused the device to obtain a fresh machine TGT. Deleting the computer account also provided a hard cutoff in the tested flow, although that is obviously much more disruptive. Disabling the computer account prevented future machine authentication and renewal, but existing stale armor remained usable in some active-session scenarios. For that reason, disable alone should not be assumed to provide instantaneous invalidation. Resetting the machine account password did not invalidate the existing machine TGT or prevent renewal of that ticket lineage.

A targeted short-lived Computer Authentication Policy may reduce the stale window by forcing more frequent machine authorization refresh under native Windows behavior. This should be evaluated carefully because of the additional Kerberos activity and the implementation differences observed during explicit renewal testing.

---

## Root Cause Discussion

I want to be careful not to overstate the internal implementation without source-level confirmation.

The functional behavior is clear:

- policy decisions using device state follow authorization represented by the machine armor,
- changing the live directory object does not retroactively change an already-issued machine TGT,
- normal machine-ticket renewal can preserve that stale authorization,
- and another KDC can accept the stale authorization even after it has replicated the revoked directory state.

Taken together, the evidence strongly supports the conclusion that the relevant device authorization is being carried in the machine TGT/PAC used as FAST armor rather than being fully re-evaluated from live directory state for every protected authentication. That design creates a revocation gap. The KDC is making a new protected-user authorization decision using device state that may have been true when the machine ticket was issued but is no longer true when the protected user authenticates.

---

## Why the Cross-KDC Result Matters

The cross-KDC test is especially important because stale directory replication is an obvious alternative explanation for this class of behavior. That explanation did not fit the observed result. DC03 explicitly reported the workstation as `AP-Revoked`. Despite that, DC03 accepted a DC01-issued machine TGT created while WS01 was `AP-Allowed` and issued a fresh protected-user TGT. When the machine TGT was replaced with a fresh revoked generation, DC03 denied the exact same protected-user authentication. The enforcing KDC therefore had the correct live state in both cases. The deciding factor was the machine armor supplied to it.

---

## Disclosure

This research was reported to Microsoft Security Response Center before publication. At the time of writing, public disclosure is being held until MSRC completes its review and provides guidance regarding disclosure.

### Disclosure Timeline

- **[08/11/2026]**: Initial behavior identified during Authentication Policy and Kerberos FAST research.
- **[08/11/2026]**: Core issue reproduced with group-based device restrictions.
- **[08/11/2026]**: Claim-based restriction persistence confirmed.
- **[08/11/2026]**: Machine-TGT renewal persistence confirmed.
- **[08/21/2026]**: TGS-stage Authentication Policy impact confirmed.
- **[08/12/2026]**: Cross-KDC validation completed.
- **[08/13/2026]**: Remediation and lifecycle testing completed.
- **[08/13/2026]**: Report submitted to MSRC.
- **[08/14/2026]**: MSRC requested additional proof-of-concept evidence.
- **[08/14/2026]**: Video PoC and supporting evidence provided to MSRC.
- **[DATE]**: MSRC final response pending.

---

## Conclusion

The original question behind this research was simple:

> When an Authentication Policy says a protected user may only authenticate from an approved device, what exactly represents that device at the moment the KDC makes the decision?

The answer turned out to have important revocation consequences. The live computer object is not the only relevant state. The authorization represented by the machine TGT used as Kerberos FAST armor can continue satisfying the restriction after the underlying device has been revoked in Active Directory. That stale authorization can permit completely fresh protected-user TGT issuance. With normal machine TGTs, the stale state can also survive ticket renewal, extending the authorization beyond the original ticket lifetime without requiring a fresh machine AS exchange. The behavior is not limited to a single policy form or KDC. I reproduced it with groups, claims, AS-stage restrictions, TGS-stage restrictions, compound authentication, and cross-domain-controller enforcement.

At the same time, the testing produced clear containment boundaries. Fresh machine authentication incorporates the current device state. Rebooting the workstation forces that refresh. Deleting the computer object provides a stronger cutoff. A short-lived Computer Authentication Policy can also reduce the stale window under native Windows ticket maintenance. The broader takeaway is that Authentication Policy device revocation is not necessarily an instantaneous directory-state decision. In the tested configurations, the lifetime and renewal behavior of the machine Kerberos armor directly influenced how long an authorization decision remained effective after the device itself had been revoked.
