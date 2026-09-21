---
title: "The Call Is Coming From Inside the House: Unauthenticated Kerberos relay and IP laundering in the Windows KDC Proxy"
date: 2026-09-20
categories: [Personal, Research]
tags: [Windows, Active Directory, KDC Proxy, Red Teaming, AD CS, PKINIT, OPSEC, Research]
published: true
---

I spent a few weeks living inside the Windows KDC Proxy, and the short version is that it does exactly what it was designed to do, which turns out to be the problem. The service takes an unauthenticated HTTPS request from the public internet, unwraps a Kerberos message from it, figures out which domain controller should handle that message, and forwards it on, and it does all of this without ever asking who you are or whether the domain you named has anything to do with the network the proxy lives on. Everything else I found sits on top of that one behavior, so before I get into the spray primitives and the certificate chain and the Windows Server 2025 crypto oddities, I want to establish how the proxy actually works and why an internet-facing relay into the heart of Active Directory authentication is the finding that matters.

## How the KDC Proxy works

Kerberos was built with an assumption that has aged badly, which is that the client and the domain controller can see each other directly on the network over TCP or UDP port 88. That assumption breaks the moment you want a laptop on a coffee shop network to authenticate against a domain controller sitting behind three firewalls, and rather than punch the raw KDC ports out to the internet, Microsoft wrapped the whole exchange in HTTPS and called it the Kerberos Key Distribution Center Proxy Protocol, documented as [MS-KKDCP]. The server side is a Windows service named KPSSVC, and the client speaks to it by POSTing to an endpoint that is almost always reachable at `https://host/KdcProxy`.

The wire format is small and worth understanding because most of what I did was manipulate it directly. A KDC-PROXY-MESSAGE is an ASN.1 SEQUENCE with three fields, and the shape of it looks like this.

- **kerb-message [0]**: an OCTET STRING holding the actual Kerberos message you would normally send to port 88, prefixed with a four byte length in the same framing TCP uses.
- **target-domain [1]**: a GeneralString naming the realm the proxy should route this message to.
- **dclocator-hint [2]**: an optional INTEGER carrying DsGetDcName flags that influence which domain controller the proxy selects.

```text
KDC-PROXY-MESSAGE ::= SEQUENCE {
    kerb-message   [0] OCTET STRING,            -- 4-byte length prefix + the raw Kerberos message
    target-domain  [1] GeneralString OPTIONAL,  -- the realm the proxy should route to
    dclocator-hint [2] INTEGER OPTIONAL         -- DsGetDcName flags
}
```

When KPSSVC receives one of these, it reads the target-domain field, calls DsGetDcName to locate a domain controller for that realm, opens a connection to whatever it finds, relays the inner Kerberos bytes, and hands the KDC's reply back to you inside another KDC-PROXY-MESSAGE. The client never talks to the domain controller and the domain controller never sees the client, which is the entire point, and it is also why the domain controller has no idea who it is really talking to.

![Request flow through the KDC Proxy](/assets/img/2026-09-20-KDC_Proxy_research/request-flow.png){: .align-center}
> *Figure 1. An unauthenticated client POSTs a wrapped Kerberos message and the proxy routes it by the target-domain field, with no check on who is asking.*

I built a small client called kkdcp to speak this protocol on its own, and then I did something more useful, which was to write a routing shim that monkeypatches the send functions inside impacket and minikerberos so that any Kerberos exchange those libraries can construct gets wrapped in the KKDCP envelope and pushed through the proxy instead of going to port 88 directly. That shim is the reason the rest of this research moved quickly, because it let me take well tested Kerberos code and aim all of it at the proxy without reimplementing Kerberos from scratch.

## Where this actually runs

None of this matters if the service is rare, so I went looking for how often KPSSVC is actually deployed, and the answer reframes the whole thing, because the defining property of the KDC Proxy is that wherever it exists it exists specifically to be reachable from the internet, which is the opposite of nearly every other Active Directory service. Remote Desktop Gateway is the most common home for it, and the coupling is tighter than most people realize, since the RDP client sets the RD Gateway host as its KDC proxy for the Kerberos authentication it does over HTTP, and if there is no KDC proxy running on that gateway the connection silently downgrades to NTLM, so any organization running a Kerberos-only RD Gateway with NTLM disabled has to stand KPSSVC up on an internet-facing box. DirectAccess enables the KDC Proxy by default and exposes it to the public internet as part of its normal configuration, its successor Always On VPN over RRAS carries the same surface on domain-joined servers that sit at the edge, and Azure Virtual Desktop uses the same gateway role to give remote users Kerberos. The newest and most relevant deployment to my research is the pattern Microsoft is actively promoting for smartcard and certificate logon from Entra-joined machines into on-premises domain resources, which puts the RD Gateway and KDC Proxy on port 443 facing the internet precisely so that certificate authentication can reach the domain controller.

That the surface is real is not really up for debate, since Microsoft shipped a wormable remote code execution fix for the KDC Proxy in CVE-2024-43639 and then patched a batch of sixteen memory corruption bugs in the surrounding RRAS code in the middle of 2025, which tells you researchers are already probing it and that Microsoft treats it as a live edge component. The footprint is not universal the way SMB or LDAP is, but it is concentrated in exactly the internet-facing remote access scenarios where an unauthenticated relay has teeth, and the ongoing push to deprecate NTLM keeps moving more Kerberos-only gateways to the edge, so the population is growing rather than shrinking.

## The design flaw, which is that it relays for anyone

The behavior I want to lead with is that KPSSVC will relay Kerberos to any domain that DsGetDcName can locate, including a domain that has no trust relationship with the proxy's own forest, and it will do this for a completely unauthenticated caller. A KDC Proxy conceptually belongs to a domain and exists to proxy for that domain's clients, so the intuitive expectation is that it would only service its own realm, and that expectation is simply wrong, because the routing decision is made entirely from the attacker-supplied target-domain field with no check that the named realm is trusted or that the requester has any business asking about it.

![The no-trust-check relay](/assets/img/2026-09-20-KDC_Proxy_research/no-trust-relay.png){: .align-center}
> *Figure 2. The proxy relays to any locatable domain, including a forged realm whose domain controller the attacker runs.*

I proved this the clean way by standing up a domain that does not exist in any trust graph. I created a forged realm called evil.lab, gave it DNS records that pointed a KDC hostname at a box I controlled, ran a listener there that logged the inbound Kerberos, and then sent the proxy a KDC-PROXY-MESSAGE with target-domain set to evil.lab, and the proxy located my fake domain controller and relayed the request to it on the first try. The same tooling reaches a genuinely trusted foreign forest just as easily, but evil.lab is the important result because samba.lab was already trusted in my lab and would not have proven the point, whereas evil.lab had no relationship to the proxy's forest at all and the proxy relayed to it anyway.

```console
# unauthenticated, against the internet-facing endpoint
$ ./kkdcp.py https://proxy/KdcProxy --target-domain evil.lab --kerb <AS-REQ>

# on the proxy, Microsoft-Windows-Kerberos-KdcProxy/Operational:
306  Rediscover KDC for domain evil.lab
309  Rediscovered KDC 10.10.20.50 (kdc.evil.lab) for domain evil.lab   <- attacker-controlled
```

There is a real boundary on this that I want to be honest about, because it is the difference between an interesting design flaw and a catastrophic one. Windows insists on a proper DsGetDcName resolution, which means the target has to look like a real, locatable Active Directory domain rather than an arbitrary host and port, so this is not a general SSRF primitive that lets you point the proxy at any TCP service you like. What it is instead is an unauthenticated open Kerberos relay into any AD-locatable KDC, and the severity of that depends heavily on one question I could answer only partially in my lab, which is whether an external attacker can get a domain of their choosing into the proxy's DsGetDcName resolution path. In my environment I controlled DNS, so making evil.lab locatable was trivial, and in a real environment an attacker would need either an existing trusted or reachable forest or some influence over how the proxy resolves domains, so I am filing the fully attacker-controlled internet KDC as an open question rather than a proven capability.

While I was mapping the routing I found that the whole decision hangs on the target-domain field and nothing else, since the inner Kerberos realm is never validated against it and a message with no target-domain is refused outright rather than falling back to the inner realm. That gives you a locator oracle for free, because the KdcProxy Operational log on the proxy records event 306 when it starts a lookup and event 309 when it succeeds, so a domain that produces a 306 with no matching 309 is one the proxy could not locate, and a domain that produces both leaks the resolved domain controller hostname and IP address in the 309 message. An unauthenticated caller can walk a list of candidate realms and learn which ones the proxy can reach and what their domain controllers are named, which is reconnaissance the caller has no right to.

## The domain controller blames the proxy

The consequence that runs through everything else is that the domain controller attributes every proxied request to the proxy's own IP address and never to the real client, and I confirmed this on every event type I could generate, so the authentication successes showed up on the domain controller as coming from `::ffff:10.10.20.12`, which is the proxy, and so did the failures, the password resets, and the certificate logons. From the domain controller's point of view the attacker does not have an IP address at all, because the only address it ever sees is that of a trusted internal server.

![IP laundering and the telemetry gap](/assets/img/2026-09-20-KDC_Proxy_research/ip-laundering.png){: .align-center}
> *Figure 3. The attacker's TLS connection ends at the proxy, so the domain controller only ever records the proxy address.*

```text
# domain controller Security event, Network Information
Client Address:   ::ffff:10.10.20.12      <- the KDC Proxy, never the attacker
Client Port:      51731
```

I want to be precise about what this does and does not buy an attacker, because it is easy to oversell and the honest version is more useful. Any detection or control that keys on the source IP as the domain controller sees it goes blind, so geographic blocking, IP reputation, conditional access tied to network location, and the classic "a hundred failed logons from one external address" heuristic all see a friendly internal box instead of an attacker, and worse than merely hiding the origin, the traffic inherits the identity of a host that is supposed to be talking to the domain controller, so it blends in better than a direct attack would. What this is not is untraceable, because the attacker's real address still exists at the proxy's transport layer, where the TLS connection terminates and where the HTTP.sys and IIS logs and any edge device in front of the proxy can see it, so the correct way to think about this is that the domain controller's Kerberos telemetry cannot recover the origin on its own and that real attribution requires joining the domain controller events to the proxy's own logs by timestamp. It is source obfuscation from the backend rather than anonymity, closer to what a reverse proxy or NAT gives you, and the reason it is worth writing about is that it is counterintuitive in a way defenders get wrong, since the instinct is to trust Kerberos that appears to originate from your own gateway, and that instinct is exactly backwards here.

## Unauthenticated spray and account enumeration

Because the proxy forwards AS-REQ messages without caring who sent them, it is an unauthenticated front door to the domain controller's pre-authentication logic, and I built a tool called kkspray to drive password spraying and account enumeration through it. The first thing worth stating is that this works against a default configuration, because the setting that governs whether the proxy accepts username and password authentication, which lives at `DisallowUnprotectedPasswordAuth` under the KPSSVC service key, defaults to zero, meaning password based AS-REQ is allowed unless an administrator has explicitly turned it off, and I confirmed the target in my lab was sitting at that default.

What made the enumeration interesting is the response taxonomy I mapped on Windows Server 2025, which inverts the usual signal in a way that helps an attacker who understands it. When I sprayed an account that exists and requires pre-authentication, a wrong guess produced no event on the domain controller at all, so the misses against real, protected accounts are silent, while a request for an account that does not exist produced a 4768 with result code 0x6, an account configured without pre-authentication produced a 4768 with code 0x0 and is therefore roastable, a wrong password against an account produced a 4771 with code 0x18, and a correct password produced a clean 4768 with code 0x0. The practical shape of that is noisy misses against nonexistent accounts and quiet hits against real ones, so a careful sprayer generates the least evidence exactly when it succeeds, and the enumeration is a byproduct because the difference between the unknown-principal response and the silent pre-auth-required response tells you which accounts are real before you ever guess a password.

```text
existing account, pre-auth required, wrong guess  ->  no event (silent)
account does not exist                            ->  4768  code 0x6
account has no pre-auth (roastable)               ->  4768  code 0x0
wrong password against a real account             ->  4771  code 0x18
correct password                                  ->  4768  code 0x0
```

## Writing to the directory through kpasswd

The proxy also forwards the Kerberos password change protocol, which rides the KDC on port 464, and I built kkpw to route impacket's kpasswd code through the KKDCP envelope so that password changes and resets travel over the same internet-facing endpoint. Getting the message construction right took some care, because the correct form uses the change-password version marker and an ASN.1 wrapped ChangePasswdData structure rather than a raw password blob, and once that was correct the results laid out as a progression from structural to functional.

A self-service password change reached the domain controller, authenticated, and was processed all the way to a policy decision, and the reason it bounced was that the account's password was younger than the domain minimum age, which is a functional rejection rather than a broken request, and the rejection was generous enough to hand me the full domain password policy including minimum length, history depth, complexity requirement, and the maximum and minimum age, so a soft rejection over the proxy leaks the policy to an unauthenticated-adjacent caller. The sharper result was a cross-account reset, where I drove a privileged credential through the proxy to reset a different account's password, and the domain controller recorded event 4724 with the target account set to my victim and the subject set to the administrator whose credential I used, which is a genuine write into the directory performed entirely through the edge and attributed to the proxy at the network layer.

```text
# domain controller Security event 4724 (password reset)
Subject
    Account Name:   Administrator
Target Account
    Account Name:   kpwtest
```

## Riding trusts and mapping them

Once I could get a ticket-granting ticket through the proxy with a single sprayed credential, I could ask for cross-realm referrals, and I built kktgs to chase those referrals through the same transport, so a single valid credential in the proxy's own realm let me request tickets that the domain controller then referred onward, and I watched the request get delivered to a trusted foreign forest's domain controller with the proxy generating a 309 that resolved to that foreign KDC. The same locator behavior that powers the relay finding also enumerates the trust graph, because probing a series of candidate realms and watching which ones the proxy can locate maps out the reachable trusts from a completely unauthenticated position.

## The HTTP front door is loose

Underneath the Kerberos semantics the proxy is an HTTP endpoint served by HTTP.sys, and I spent time with a raw TLS harness called kkhttp looking at how strict that layer is, and the answer is that it is strict in some places and loose in exactly the places that help an attacker slip past a filtering device. The Content-Type header is not enforced, so a request with a missing or arbitrary Content-Type still forwards, which defeats any web application firewall rule that keys on the documented Kerberos content type. The URL path canonicalization is loose enough that requests to `/kdcproxy`, to a doubled `//KdcProxy`, and to a traversal-encoded path all reach the same handler, which defeats path-based access control lists that only know the canonical spelling. The responses also carry a malformed Content-Type whose value is the body length as a bare number rather than a media type, and the Server header identifies the endpoint as Microsoft-HTTPAPI, so fingerprinting the service from the outside is easy. The layer is not uniformly weak, since a non-POST method draws a reset, a duplicated Content-Length draws a 400, and a bad Transfer-Encoding draws a 501, so the hardening is real but it sits next to canonicalization and header handling that a filtering proxy in front of KPSSVC cannot rely on.

## The domain controller locator hint, and what it does not let you do

The dclocator-hint field is the most interesting piece of the envelope because it lets an unauthenticated caller influence the DsGetDcName call the proxy makes, and I built kkhint to inject named DS_ flags and watch what the domain controller locator did with them, and this is also the place where I corrected a belief I had carried for most of the research. My early testing suggested the proxy applied a fixed allow mask of 0xFF17FFEF to the injected flags, and that was wrong, because when I echoed the resulting flags back out of the locator failure events I could see that individual defined flags pass through unmodified as the base value 0x601 combined with whatever I injected, and the 0xFF17FFEF value only ever appeared as the locator's own normalization of a probe that set every bit at once, so it was an artifact of the maximal case and not a per-bit filter the proxy imposes.

The real limiter is DsGetDcName's own combination validation, and it happens to cut against the attacker in a useful way. When I injected DS_PDC_REQUIRED or DS_GC_SERVER_REQUIRED, the locator returned an invalid-flags error rather than honoring them, and the reason is that the proxy's base flags already include DS_KDC_REQUIRED, which the API forbids combining with the PDC and global catalog requirements, so an attacker cannot force the proxy to hammer the PDC emulator or steer toward a global catalog, which is the outcome I initially thought was possible and which turns out to be blocked by the base flags. The flags that do survive and run cleanly are the ones like writable-required, try-next-closest-site, avoid-self, and the time server preferences, so there is genuine unauthenticated influence over domain controller selection, just not over the two roles you would most want to target.

```text
DS_PDC_REQUIRED         0x80     ->  INVALID_FLAGS  (base already sets DS_KDC_REQUIRED)
DS_GC_SERVER_REQUIRED   0x40     ->  INVALID_FLAGS  (base already sets DS_KDC_REQUIRED)
DS_WRITABLE_REQUIRED    0x1000   ->  accepted
DS_TRY_NEXTCLOSEST_SITE 0x40000  ->  accepted
DS_AVOID_SELF           0x4000   ->  accepted
```

The invalid-versus-valid distinction is itself an oracle, since a valid combination against a nonexistent domain fails differently than an invalid combination does, and in a real multi-domain-controller environment the satisfiable-versus-unsatisfiable split becomes a remote way to probe which roles exist. I also confirmed a small parser quirk while I was here, which is that a positive integer with the top bit set is rejected as too long, but a negative integer smuggles the same all-bits-set value straight through, so the length check is bypassed by signedness.

## Certificate to ticket to service, all through the proxy

The finding that ties this surface to the rest of my work is that PKINIT travels through the proxy cleanly, so a client certificate is enough to obtain a ticket-granting ticket end to end over the internet-facing endpoint with no domain password and no line of sight to a domain controller. This matters because certificate based logon is exactly the scenario Microsoft is pushing the KDC Proxy for, and it means any Active Directory Certificate Services misconfiguration that yields a certificate, which is the entire ESC family that my other tooling already chases, becomes a remote and IP-laundered domain foothold through the one exposed box.

![Certificate to ticket to service through the proxy](/assets/img/2026-09-20-KDC_Proxy_research/pkinit-chain.png){: .align-center}
> *Figure 4. A certificate becomes a ticket-granting ticket and then a service ticket, every hop sent through the proxy and attributed to it.*

Building the PKINIT client honestly was most of the work, because the standard library path in minikerberos depends on oscrypto, which fails against modern OpenSSL, so I wrote kkpkinit to do the certificate handling and RSA signing with the cryptography library, the CMS SignedData construction with asn1crypto, and the final symmetric decryption with the minikerberos enctype tables, which sidesteps the broken dependency entirely and runs on a current Kali box. The interesting part is that Windows Server 2025 walked me through its PKINIT hardening one rejection at a time, and I will cover that in its own section, but once I satisfied it the result was unambiguous, because I minted a certificate for a test user with certipy, pushed the PA-PK-AS-REQ through the proxy, and got a ticket-granting ticket back, and the domain controller logged a 4768 with pre-authentication type 16, a result code of zero, the certificate issuer and serial and thumbprint filled in, and a client address that was the proxy.

```text
# domain controller Security event 4768 (TGT request)
Pre-Authentication Type:  16                 <- PKINIT
Result Code:              0x0
Certificate Issuer Name:  reflect-CA
Certificate Thumbprint:   7F13FF5239883ACDC74D8F5302D18E972D02EF16
Client Address:           ::ffff:10.10.20.12   <- the KDC Proxy
Response ticket hash:     EsbQYL9tuAWIeT+13TvUCx95ghSaqeurummMb9a0MoM=
```

I then completed the chain with kkgetst, which loads that certificate-derived ticket and requests an actual service ticket through the same proxy, and the domain controller obliged with a 4769 for the target service, again sourced from the proxy address. The detail I like most is that the 4769 carried a request ticket hash that exactly matched the response ticket hash from the earlier 4768, so the domain controller's own logs cryptographically chain the certificate that issued the ticket-granting ticket to the ticket-granting ticket that bought the service ticket, and every hop in that chain is attributed to the proxy's IP with no domain credential involved anywhere.

```text
# domain controller Security event 4769 (service ticket request)
Service Name:          DC01$
Client Address:        ::ffff:10.10.20.12
Request ticket hash:   EsbQYL9tuAWIeT+13TvUCx95ghSaqeurummMb9a0MoM=   <- matches the 4768 response hash
```

Certificate in, usable domain access out, laundered through the edge.

## What Windows Server 2025 taught me about paChecksum

The reason my first several PKINIT attempts failed is a genuinely interesting piece of the Windows Server 2025 crypto hardening, and since it stands on its own I want to lay out the whole progression, because each rejection was a real interop detail rather than a bug in my code. My first well-formed request used the 1024-bit Oakley Group 2 for the Diffie-Hellman exchange and came back with a padata-type-not-supported error, which is the KDC declining the weak group, and moving to the 2048-bit Group 14 cleared it. The next rejection was error 79, which is the KDC telling me the request checksum must be included even though I was already sending the RFC 4556 paChecksum, and unwinding that led me to two separate problems.

The first problem was that the Kerberos request body carries a flags field that must be a full 32-bit bitstring, and the ASN.1 library I used trims trailing zero bits per strict DER, so my kdc-options was sixteen bits wide, the domain controller re-expanded it to the canonical 32-bit form before hashing, and my SHA-1 checksum over the shorter encoding no longer matched. The second and more important problem is that Windows Server 2025 extended the PKAuthenticator structure with a second checksum called paChecksum2, documented in MS-PKCA, which carries a SHA-256 hash of the request body alongside the original SHA-1 one, and the current KDC requires it on the finite-field Diffie-Hellman path. Once I sent both checksums over the canonical body the ticket came back.

The part worth publishing is the asymmetry I confirmed with a small matrix, and it lines up with what Microsoft's own engineers described on a public protocol mailing list back in January 2025, which I was able to reproduce as a runnable set of cases in September 2026, twenty months later, still present. The finite-field path with only the SHA-1 checksum is rejected, the finite-field path with both checksums works, the elliptic-curve path with only the SHA-1 checksum works, and dropping the SHA-1 checksum entirely is rejected on both paths.

| Key exchange | paChecksum (SHA-1) | paChecksum2 (SHA-256) | Result |
| --- | --- | --- | --- |
| FFDH (Group 14) | present | absent | rejected, error 79 |
| FFDH (Group 14) | present | present | ticket issued |
| ECDH (P-256) | present | absent | ticket issued |
| ECDH (P-256) | absent | absent | rejected, error 79 |

The way I read that is that Windows Server 2025 still mandates the SHA-1 paChecksum on both key-exchange paths, because RFC 4556 says it must be present and omitting it fails everywhere, but it additionally requires the SHA-256 paChecksum2 only on the finite-field path, so the elliptic-curve path still accepts a request body bound solely by SHA-1. The entire purpose of paChecksum2 is to move that binding off a collision-broken hash, and the hardening was applied to one key-exchange path and not the other, which leaves the elliptic-curve path carrying exactly the weakness the new checksum was introduced to close, and the elliptic-curve path is the more attractive one to deploy because its messages are several hundred bytes smaller.

I want to be careful about the weight of this, because it is a defense-in-depth regression rather than a practical attack. Turning the SHA-1-only binding into an exploit would need a chosen-prefix SHA-1 collision on a Kerberos request body that stays useful after the collision, executed from a man-in-the-middle position on the TLS-protected channel, which is deep in the theoretical weeds, and Microsoft already knows about it since it came out of their own thread. The value here is a reproduced, dated, key-exchange-complete matrix showing that the gap is still open, and it fits into the broader picture of the Windows Server 2025 crypto stack rewrite applying its SHA-1 deprecation unevenly across the paths it touches.

While I was in this area I also checked the RFC 8070 freshness extension, which exists to stop a certificate holder from precomputing PKINIT requests offline, and a bare AS-REQ came back with a pre-authentication-required error whose method data did not offer a freshness token, so the KDC supports PKINIT but does not enable freshness by default, which means nothing stops that offline precomputation unless an administrator turns the extension on. It is a minor point, but it is a real one and it confirmed that the proxy relays the initial error round cleanly.

## What I could not break

The honest measure of a surface is what holds up, and several things did, which is what makes me trust the findings that did not. I ran a mutational fuzzer against the parser for tens of thousands of iterations with the service under full page heap and Windows Error Reporting watching for crashes, and it stayed clean, so the memory safety of the parser is solid on a patched build and the CVE-2024-43639 class of bug appears genuinely closed rather than merely quieted. I threw the denial-of-service patterns at it that tend to work on hand-rolled request handlers, the slow reads and the oversized bodies and the connection games, and it held. I tried smuggling a second realm into the request through BER encoding tricks and the parser rejected it.

The most instructive negative was the delegation surface, because I fully expected the proxy to let me smuggle an S4U request somewhere it should not go, and it did not, for a structural reason worth stating plainly. I routed S4U2self and S4U2proxy through the proxy with kks4u, and every delegation decision was made and enforced by the domain controller on the identical request, so a self-ticket for a normal user came back forwardable while the same request for an account marked sensitive and not-for-delegation came back non-forwardable, which is the Bronze-Bit-class protection working correctly through the proxy rather than being bypassed by it. When I tried S4U2proxy with a service that had no delegation configured the KDC returned a bad-option error, and when I aimed a cross-realm S4U request at a foreign forest's domain controller the ticket was rejected as not-for-us because it was cryptographically bound to the realm that issued it. The pattern under all of that is that the proxy is a dumb forwarder, the KDC enforces every authorization decision on the same bytes it would have seen over port 88, and tickets are bound to their issuing realm's krbtgt key, so routing confusion can get an authenticated operation rejected but it cannot smuggle it past a check, which bounds the entire class of routing-based delegation attacks and is the reason the relay finding is about reach and reconnaissance rather than about privilege.

## What this actually gets you

Pulling the threads together, there is one genuine design flaw here and a stack of reachability primitives that compose on top of it. The design flaw is the relay, because an unauthenticated internet caller can drive Kerberos into any AD-locatable KDC including untrusted forests, and can enumerate the trust graph and the domain controllers behind it as a side effect, which is a boundary a KDC Proxy has no business crossing. Everything else that looks like an attack, the spraying and the account enumeration and the kpasswd reset and the certificate-to-ticket chain, is the domain controller behaving exactly as designed, reached remotely and attributed to the proxy, so the proxy is not granting new Kerberos capabilities so much as it is granting unauthenticated internet reach to the ones that already exist and stripping the origin off them on the way through.

That distinction is the honest impact statement. If you already have a valid credential or a certificate, the proxy turns it into a remote and source-obfuscated foothold, and the certificate case is the nastiest because it welds any AD CS enrollment weakness onto an internet-facing entry point with no domain password required. If you have nothing, the proxy still gives you unauthenticated spraying against a default configuration, account and trust enumeration, a domain controller locator oracle, and a password policy leak, all from the edge and all showing up on the domain controller as your own gateway. The crypto findings are lower weight and I have tried to label them that way, since the paChecksum2 asymmetry is a defense-in-depth regression that Microsoft already tracks and the missing freshness enforcement is a hardening gap rather than a break. The memory safety and denial-of-service and delegation surfaces held up under real testing, and I am including those negatives on purpose, because a writeup that only lists what broke is not telling you how sturdy the thing actually is.

## Detection and hardening

The counterintuitive part for defenders is the one to internalize first, which is that malicious Kerberos coming through the proxy shows up in your domain controller logs as originating from a trusted internal server, so the reflex to trust proxy-sourced authentication is exactly the wrong reflex and proxy-sourced Kerberos should be treated as a pivot point into the proxy's own transport logs rather than as friendly traffic. The single highest-value hunt is the certificate-to-ticket chain, which has a clean signature, since a 4768 with pre-authentication type 16 and populated certificate information and a client address equal to the proxy, followed by a 4769 whose request ticket hash matches that 4768's response ticket hash from the same proxy address, is a high-confidence single-actor sequence, and enriching it with whether the certificate's account has any history of smartcard logon separates the real attacker from the legitimate remote user.

The spray and reset activity needs detections that do not depend on source IP, because the proxy collapses every attacker into one internal address, so keying on per-account failure rates and on the breadth of distinct accounts touched from proxied authentication works where per-IP thresholds do not, and watching for the silent-hit inversion where a spray suddenly goes quiet against specific accounts is worth building. The DsGetDcName hint abuse is visible in the KdcProxy Operational log as locator flags beyond the baseline and as the valid-versus-invalid failure split, and the relay itself shows up as locate attempts and successes for realms the organization does not own.

On the hardening side, the setting that closes the most is `DisallowUnprotectedPasswordAuth`, which defaults to zero and should be set to one so the proxy stops accepting username and password AS-REQ, since that single change removes the spray and the kpasswd paths. Restricting which realms the proxy will locate and relay to addresses the root design flaw directly, ensuring the proxy's edge logs capture source IP and are retained and correlated to domain controller telemetry restores the attribution that the laundering removes, and enabling the RFC 8070 freshness extension closes the offline precomputation gap for certificate logon. The theme running through all of it is that the KDC Proxy sits at the boundary between the internet and your authentication core, and it should be treated with the suspicion that position deserves rather than as a transparent pipe.

## References

- [MS-KKDCP] Kerberos Key Distribution Center Proxy Protocol, Microsoft Open Specifications.
- [MS-PKCA] Public Key Cryptography for Initial Authentication (PKINIT) in Kerberos, section 2.2.3, for the PAChecksum2 extension.
- RFC 4556, Public Key Cryptography for Initial Authentication in Kerberos.
- RFC 8070, Public Key Cryptography for Initial Authentication in Kerberos Freshness Extension.
- CVE-2024-43639, Windows KDC Proxy remote code execution.
- The Windows Server 2025 PKINIT paChecksum2 discussion on the samba cifs-protocol mailing list, January 2025.
