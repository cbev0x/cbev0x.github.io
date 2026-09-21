---
title: "Letting KDC Proxy Do the Dirty Work: DNS Poisoning for Credential Harvesting"
date: 2026-09-21
categories: [Personal, Research]
tags: [Windows, Active Directory, KDC Proxy, Red Teaming, OPSEC, Detection, Research]
published: true
---

The Windows **KDC Proxy** (KPSSVC, the service behind MS-KKDCP) is one of those components that quietly ends up internet-facing and rarely gets a second look. It fronts Kerberos over HTTPS so external clients (Always On VPN device tunnels, RD Gateway, Azure-joined machines reaching an on-prem realm, SMB over QUIC) can authenticate without exposing raw 88/464. By design it accepts **unauthenticated** callers, because the whole point is to help a client that has no tickets yet get some.

I spent a while mapping its trust decisions, and the short version is that the proxy trusts things it never verifies in *both* directions:

- **Inbound.** No client authentication by default, and the one binding-level knob operators reach for to add it doesn't actually enforce anything. The control that works is a service setting that ships disabled.
- **Outbound.** It locates a "DC" via DNS and a CLDAP ping and relays your Kerberos there without ever confirming the host is a real domain controller. Point its name resolution at a box you control and it forwards victims' pre-authentication to you.

This post walks the inbound and outbound findings, the measured cost of the DNS prerequisite that gates the outbound abuse (this is where most of the "it works / no it doesn't" folklore lives), and **EvilKDC**, a tool that stands up the rogue side of the chain in one terminal. Everything here was tested in a lab against a patched Windows Server KDC Proxy and reported to MSRC prior to publication.

## Prior work

None of the primitives here are invented from scratch, and the people who got there first deserve top billing:

- **DogWhistle** (1njected) weaponized the KDC Proxy as an attack surface (ASREPRoast, Kerberoast, spray and bruteforce *through* the proxy) and called out the source-IP laundering and the DirectAccess client-cert reachability quirk.
- **Dementor** (matrixeditor) is a Responder-style toolkit that already includes a rogue Kerberos KDC for ASREQ-roasting (`PA-ENC-TIMESTAMP` capture), driven by LLMNR/NBT-NS/mDNS poisoning.
- **mitm6** (dirkjanm) is the DHCPv6 primary-DNS-takeover primitive that makes the same-subnet path viable.
- **kerbrute** (ropnop) covers pre-auth username enumeration and RC4 downgrade.

What I'm adding is the **KDC-Proxy delivery vector**, using the internet-facing proxy itself to funnel external clients' pre-authentication to a rogue KDC, plus a measured map of exactly what that requires, because the prerequisite is where this technique is usually over- or under-sold.

## How the proxy finds a "DC"

When a KKDCP request arrives, KPSSVC has to forward the Kerberos message to a real KDC. It does that with `DsGetDcName`: DNS SRV lookups under `_msdcs.<realm>` for the DC, an A-record resolution of the DC's hostname, and a CLDAP NetLogon "ping" to confirm the candidate answers for that realm. Whatever that process returns is where the proxy relays. Two things fall out immediately. The proxy's choice of DC is only as trustworthy as its DNS, and the real DC sees the *proxy's* IP as the source of every relayed request.

## The inbound client-cert control that isn't

Out of the box the KDC Proxy endpoint is unauthenticated. Any host that can reach `https://<proxy>/KdcProxy` can drive it, and since the whole toolkit of KKDCP recon (spray, ASREPRoast, account-state oracle) rides that endpoint, is already the interesting part DogWhistle documented.

The obvious hardening move is to require a client certificate. Operators reach for the HTTP.sys binding setting:

```
netsh http show sslcert
...
(snipped)
...
    Negotiate Client Certificate : Enabled
```

That reads like "clients must present a cert now." It isn't. `Negotiate Client Certificate` is a *request*, not a *requirement*. Send an empty certificate and the handshake completes anyway:

```
* TLSv1.3 (IN),  TLS handshake, Request CERT (13):
* TLSv1.3 (OUT), TLS handshake, Certificate (11):   <- 8 bytes: "I have no cert"
* TLSv1.3 (OUT), TLS handshake, Finished (20):
* Established connection to 10.10.20.12 (port 443)
> POST /KdcProxy HTTP/2
```

The server asked for a cert, the client declined, and the request proceeded. No binding-level option (`Reject Connections`, `DS Mapper`) turns that into a hard requirement.

The control that *does* enforce lives in the service, not the binding:

```
HKLM\SYSTEM\CurrentControlSet\Services\KPSSVC\Settings
    HttpsClientAuth    REG_DWORD    0x0        <- default
```

Set `HttpsClientAuth = 1` and KPSSVC forces the connection down to HTTP/1.1, demands the client certificate, and rejects the certless request across both the recon and the relay paths. But it is **off by default**, and it is not the knob most people find first.

So the inbound boundary is a config trap. It's unauthenticated by default, the intuitive setting is a decoy, and the effective setting ships disabled. This also explains the DirectAccess observation from prior work. The cert is enforced at the DA edge, and if the KPSSVC box behind it has `HttpsClientAuth = 0`, reaching the proxy directly sidesteps the requirement entirely.

## Outbound relay to a "DC" it never verifies

Now the direction that turns this from recon into credential theft. Because the proxy relays to whatever `DsGetDcName` returns, if you can influence what it resolves for a realm's DC, it connects out to your host and forwards the victim's Kerberos to you.

The CLDAP ping looks like validation, but it only checks that the responder *claims* to serve the realm. It does not verify the responder is a genuine DC. In testing, a NetLogon response carrying a **completely bogus domain GUID** was accepted for the real realm. `nltest /dsgetdc` happily returned the rogue host and a made-up GUID that didn't match the domain's actual one. There is no cryptographic binding of DC identity at this stage; that only comes later in the Kerberos exchange itself, which the rogue KDC is capturing rather than completing.

Two honest bounds on the reach, measured rather than assumed:

- The redirect targets an **attacker-chosen host on fixed port 88**. The proxy ignores an attacker-supplied SRV port and dials 88 at the resolved address, so it's "arbitrary host, fixed Kerberos port," not arbitrary host:port.
- The KDC host and the CLDAP-validation host are the same host, because `DsGetDcName` derives the ping target from the same record set and validates by source address, so you can't split them.

And everything the real DC eventually logs is attributed to the **proxy's** source IP. Recon and relay alike are laundered.

## The prerequisite, measured

The catch, and the reason this technique gets mis-stated in both directions, is that to redirect the proxy's DC resolution you need **network position over its name resolution, not any Active Directory privilege.** I measured each tempting shortcut directly instead of trusting folklore:

| Path to redirect the proxy's DC resolution | What it needs | Works? |
|---|---|---|
| Overwrite the DC-locator records in AD (SRV/A) | DNS-admin or delegated rights | No for normal users. The `_msdcs` locator chain is `SELF`-only-write and both zones are `Secure` |
| Non-secure DNS dynamic update | zone misconfig (`NonsecureAndSecure`) | Environment-specific; secure by default |
| A-record-only spoof (mitm6 default) | resolver / same-subnet position | **Insufficient.** `DsGetDcName` selects via SRV; a truthful SRV points at the real DC |
| Serve poisoned **SRV *and* A** as the proxy's resolver | resolver position, no AD rights | **Yes.** Full redirect, and the CLDAP check does not detect the impersonation |

A few specifics worth calling out because they overturn common assumptions:

- **Standard-user ADIDNS does not help.** Authenticated Users can create *novel* nodes in the DNS zones, but every DC-locator record you'd want already exists and is owned `SELF` (the DC's machine account). Attempts to create the site-scoped or generic locator names come back "object exists," and the DACL grants normal principals only `GenericRead`. The additive ADIDNS trick lands on names nothing queries.
- **There is no NetBIOS/LLMNR fallback.** When DNS resolution of the DC-locator records fails, the SRV-based locator does not drop to NBT-NS/LLMNR/mDNS. You cannot Responder your way in when DNS is answering; you have to *be* the resolver.
- **A-record spoofing alone fails.** This is the one that trips people up. mitm6 spoofs A/AAAA, and that is not enough, because `DsGetDcName` picks the DC from the SRV record, so if the SRV resolves honestly the proxy goes to the real DC no matter what the A record says. You need the SRV poisoned too.

So the real floor is **unauthenticated, same-subnet** (become the proxy's DNS via mitm6's DHCPv6 takeover, then serve poisoned SRV+A), or any other resolver position, whether that's DHCP-assigned DNS you can influence, a compromised resolver, or admin on the proxy host. Not "any domain user," and not "anyone who can run Responder." Stating that precisely is what keeps the finding credible.

## Putting it together with EvilKDC

[EvilKDC](https://github.com/cbev0x/EvilKDC) stands up the rogue side of this chain in a single terminal:

- a **scoped DNS responder** that answers the DC-locator SRV records and the DC-host A record for one target realm (and refuses everything else, so it doesn't disrupt unrelated resolution),
- a **NetLogon CLDAP responder** that satisfies `DsGetDcName`,
- a **KDC capture listener** that elicits `PA-ENC-TIMESTAMP` and writes hashcat-crackable `$krb5pa$` lines.

Because the dangerous half, taking over the segment's DNS, can knock a subnet offline if done carelessly, that step is deliberately *not* built in. It stays a conscious, scoped mitm6 invocation in a separate terminal, or you supply resolver position some other way. A `--check` mode verifies the listeners and, given a proxy URL, fires a probe and tells you whether the proxy is actually resolving the realm to you (`REDIRECT LIVE`) before you rely on it.

The capture path in practice:

```
[*] 10.10.20.12  CLDAP ping (DnsDomain='REFLECT.LAB') -> answered as DC for REFLECT.LAB
[*] 10.10.20.12  AS-REQ testuser@REFLECT.LAB (no pre-auth) -> PREAUTH_REQUIRED
[+] CAPTURED  testuser@REFLECT.LAB  etype=AES256(18)  hashcat -m 19900
    $krb5pa$18$testuser$REFLECT.LAB$8ca35843...b851b3
```

```
$ hashcat -m 19900 evilkdc_loot.txt wordlist.txt
$krb5pa$18$testuser$REFLECT.LAB$8ca35843...b851b3:Password123!
```

Cracking is offline and lockout-free, since the real KDC never sees a guess. There's also a `--downgrade` flag that offers RC4 only in the pre-auth hint (hashcat mode 7500), though a modern client with AES keys will typically decline it.

A note on scope. Each component of this chain was validated in the lab, the unauthenticated relay through the proxy, the CLDAP-accepts-a-bogus-DC result, the DNS redirect via a controlled resolver, and the capture-and-crack. Driving the whole thing as one continuous run from a stock Windows client wasn't reproduced, because the Windows KDC Proxy *client* path only engages when the machine has no line of sight to a DC (the external-client state the feature exists for), which a flat lab subnet doesn't present. That's the product working as designed on the client side; the server-side trust decisions are the point.

## Detection & hardening

If you run a KDC Proxy:

- **Set `HttpsClientAuth = 1`.** It's the only setting that actually requires client certs at the service. Do not rely on the binding's "Negotiate Client Certificate."
- **Restrict the proxy's reachability** to its intended front-end, so the KPSSVC endpoint isn't directly hittable.
- **Protect DC-locator DNS integrity** and alert on changes to `_msdcs` SRV records.
- **Close the same-subnet DNS-takeover path**: disable IPv6 if unused, or deploy RA-Guard / DHCPv6-Guard.

To detect the relay in flight:

- The KDC Proxy host making outbound 88/464 connections to **unexpected IPs** that aren't your DCs.
- **Mass pre-auth failures** for external / KKDCP clients. Authentication fails through a rogue KDC, so a spike of failures from proxy-fronted clients is a strong signal.
- New IPv6 DNS servers appearing on member hosts, and DHCPv6 traffic from non-DHCP hosts.
- CLDAP NetLogon responses whose domain GUID doesn't match the real domain.

## Wrapping up

The KDC Proxy is a small service with an outsized trust surface. It's unauthenticated by default, the hardening knob doesn't harden, and the outbound relay treats DNS plus an unauthenticated CLDAP reply as proof of a domain controller's identity. None of the individual pieces are exotic. What matters is seeing that the component trusts both directions, and pinning down exactly what an attacker needs to exploit the outbound side. Tooling and the full measurement notes are on [GitHub](https://github.com/cbev0x/EvilKDC); reported to MSRC prior to publication.
