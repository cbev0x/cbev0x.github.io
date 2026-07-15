---
title: "Kerberos to an IP Address, Part 1: What IP SPN Actually Does"
date: 2026-07-15
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Research]
published: true
---

For as long as most of us have worked with Active Directory, one rule held: Kerberos needs a
name. Connect to a file share by hostname and you get a Kerberos ticket. Connect to the same
share by its raw IP address and you drop to NTLM. That behavior is old, it is deliberate, and
it is quietly changing. This series is about the mechanism that changes it, why it was built
that way, and what it means as Microsoft pushes NTLM toward the exit.

This first part is pure mechanism. No attacker tooling, no exploitation. Just what the feature
is, how the client decides, and what the wire and the logs show at each step. The later parts
build on this foundation, so it is worth getting the internals exact.

## The old rule, and why it existed

Kerberos authenticates you to a *service*, and it identifies that service by a Service
Principal Name (SPN) such as `cifs/fileserver.contoso.com`. When a client wants to reach a
service, it asks the KDC for a ticket to that SPN. The KDC looks up which account owns the SPN,
pulls that account's key, and encrypts the ticket with it. Only the real service, holding the
same key, can decrypt the ticket. That lookup is the whole game: the SPN is the index into
"whose key do I seal this with."

An IP address is not an SPN. There is no account in the directory that owns
`cifs/192.168.1.50` by default, so the KDC has nothing to look up, no key to select, and no
ticket to issue. Historically the client did not even try. When you connected to a resource by
IP literal, the Kerberos SSP looked at the target, saw an address instead of a name, and
declined to attempt Kerberos at all. The negotiation fell to NTLM, which has no such
requirement because it never needed a directory lookup to pick a key.

This was not an oversight. Binding a service identity to an IP address is awkward: addresses
are ephemeral, they get reassigned, and two services can share one. Requiring a name kept the
SPN-to-key mapping clean and unambiguous, and that same property is a large part of why
Kerberos has historically resisted relay attacks that plague NTLM.

## TryIPSPN: not new, newly relevant

The switch that changes this is a client-side registry value called `TryIPSPN`, and it is
older than most people expect. It has existed since Windows 10 1507 and Windows Server 2016. It
lives here:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
    TryIPSPN  (REG_DWORD)  = 1
```

When set, it tells the Kerberos client to *attempt* Kerberos for an IP-literal target instead
of vetoing it up front. For roughly a decade this was an obscure compatibility knob almost
nobody enabled, because there was rarely a reason to. NTLM handled IP-based connections fine,
and enabling `TryIPSPN` without a corresponding IP-based SPN registered just produced a failed
Kerberos attempt followed by the same NTLM fallback.

What makes it relevant now is NTLM deprecation. Microsoft has been steadily reducing NTLM's
footprint, with the stated goal of disabling it by default in a future release. IP-based
connections are one of the classic triggers that force an NTLM fallback, so if you want to kill
NTLM in an estate, you have to give those connections a Kerberos path. `TryIPSPN` plus an
IP-based SPN is that path. A knob that sat unused for ten years is about to become load-bearing
in hardened environments, which is exactly why it is worth understanding in detail before it
shows up everywhere.

One important note on scope for anyone testing this alongside the newer NTLM-deprecation work:
IP SPN is independent of IAKerb and LocalKDC. Those are separate mechanisms, and as of this
writing they ship only in preview channels, not stable. Everything in this series was validated
on stable Windows 11 (25H2) and Windows Server 2025 with the classic Kerberos-then-NTLM
negotiation stack, so the behavior described here is what a current, patched, non-preview estate
does.

## The two halves: client knob and service SPN

Making Kerberos-to-IP work takes two independent pieces, on two different machines.

The client side is `TryIPSPN`, above. It governs whether the *initiator* will even attempt
Kerberos when the target is an address. It is read by the Kerberos SSP at logon or service
start, so setting it does not take effect on an already-running session. A reboot or fresh
logon is required for the SSP to pick it up, which is a common early stumbling block when
testing.

The service side is an IP-based SPN registered on the account that owns the service. For a host
at `192.168.1.50`, that is an SPN like `host/192.168.1.50` registered on that machine's computer
account. Standard SPN rules apply: the value must be unique in the forest, and registering it
requires appropriate write access to the target account (the mechanics of which are their own
topic, covered in Part 2).

Neither half alone does anything. `TryIPSPN` with no matching SPN produces an attempt that
fails to resolve. An IP SPN with `TryIPSPN` unset is never requested. Both together produce
working Kerberos to an IP.

## Watching the client decide: three states

The clearest way to understand the mechanism is to watch a single client access the same target
by IP under three configurations and observe exactly where each one lands. The evidence comes
from two logs: the client's `Microsoft-Windows-NTLM/Operational` channel (which records NTLM
fallbacks with a reason code, on Windows 11 24H2/25H2 and Server 2025), and the KDC's Security
log on the domain controller (event 4769, service ticket requests).

### State A: default, TryIPSPN unset

With `TryIPSPN` not present, an SMB access to a raw IP falls to NTLM, and the NTLM operational
channel records the reason plainly:

```
Reason ID: 7
Reason: The target name contains an IP address.
```

The client never contacts the KDC about this target. There is no 4769 on the domain controller
for an IP-based SPN, because the client made a purely local decision: the target is an address,
so Kerberos is off the table before any request leaves the machine. Reason 7 is a categorical
veto. This is what every default estate looks like today.

### State B: TryIPSPN set, no IP SPN registered

Set `TryIPSPN=1` on the client, reboot, and access the same IP with no IP SPN registered
anywhere. The access still falls to NTLM, but the reason code changes, and the change is the
whole point:

```
Reason ID: 6
Reason: The target name could not be resolved by Kerberos or other protocols.
```

Reason 6, not reason 7. The categorical veto is gone. The client now *engages* its resolution
logic for the IP target, attempts to resolve it to a usable SPN, and only falls to NTLM after
that resolution comes up empty. Critically, in this state the client still does not send a
request to the KDC: there is no 4769 for the IP-based SPN on the domain controller. The
resolution fails locally, before any TGS request crosses the wire, because there is nothing
registered for the client to resolve the address to. `TryIPSPN` removed the veto but the
absence of a registered SPN means the attempt dies at the local resolution stage.

A useful secondary observation from this state: a name-based Kerberos access performed
immediately after these failed IP attempts still succeeds and still produces a normal ticket.
The failed IP resolution does not poison the client's broader Kerberos behavior or pin it into
NTLM for other targets.

### State C: TryIPSPN set, IP SPN registered

Now register `host/<target-IP>` on the target's computer account, keep `TryIPSPN=1`, and access
the IP again. This time the client obtains a real Kerberos service ticket:

```
Cached ticket:
  Server: cifs/<target-IP> @ REALM
  KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
```

No NTLM event is produced, because Kerberos succeeded. On the domain controller, a 4769 now
appears for the request. The only variable that changed between State B and State C is whether
an SPN exists in the directory for that address. That is the entire gate: with `TryIPSPN`
engaged, the presence or absence of a registered IP SPN is the single thing standing between a
local resolution failure and a working ticket.

The progression reason 7, then reason 6, then a ticket is the mechanism in three observations.
Veto, then attempt-but-unresolved, then resolved.

## A detail worth noting: HOST covers CIFS

There is a subtlety in State C that matters for understanding the feature's reach. The SPN
registered was `host/<target-IP>`, but the SMB access requested `cifs/<target-IP>`, and it
still worked. This is the KDC's long-standing implicit mapping of the CIFS service class onto
the HOST class, and it applies to IP-literal SPNs exactly as it does to hostname SPNs. In
practice, a single `host/<IP>` registration satisfies the HOST-class services (SMB among them)
at that address, rather than requiring a separate SPN per service. This is standard Kerberos
behavior, not specific to IP SPN, but it is worth stating because it means one registration
covers more surface than a literal reading of "I registered host, not cifs" would suggest.

## Where this leaves us

The mechanism is small and the rule is clean: Kerberos to an IP address is not magic and not a
new protocol. It is the old SPN-to-key model applied to an address instead of a name, gated on
a client knob that removes a decade-old veto and on an SPN existing in the directory. On a
current, patched Windows Server 2025 estate, it works, and it is going to become more common as
NTLM is retired.

Part 2 looks at the registration side in detail: what it actually takes to place an IP-based
SPN on an account, why the obvious low-privilege path is blocked by a specific directory
validation, and what that means for who can and cannot create these SPNs. That boundary turns
out to be more interesting, and more reassuring, than it first appears.

---

*This series documents original lab research conducted in an isolated environment. It is
educational and defensive in intent. Later parts that touch coercion behavior and detection are
written at the behavioral level and were held pending coordinated disclosure where appropriate.*
