---
title: "IAKerb: Kerberos When You Cannot Reach a KDC"
date: 2026-08-05
categories: [Personal, Research]
tags: [Windows, Active Directory, NTLM, Kerberos, Research]
published: true
---

## The gap IAKerb fills

Kerberos puts the work on the client. To get a Ticket Granting Ticket the client runs an AS exchange against a KDC, and to get a service ticket it runs a TGS exchange against that same KDC. Both require the client to reach a domain controller directly.

When it cannot, classic Windows behavior falls back to NTLM. A segmented network, a VPN that blocks port 88, a branch office with no local DC: in all of these the client has no line of sight to a KDC, and NTLM has historically been the safety net underneath.

IAKerb removes that excuse. It keeps Kerberos as the authentication protocol even when the client cannot talk to a KDC on its own.

## The role inversion

The core idea is that the client stops being the one who contacts the KDC. Instead the client proxies its KDC messages through the server it is authenticating to, and the server relays them to the KDC on the client's behalf.

This matches how networks are usually built. Servers tend to be well connected and able to locate a KDC. Clients, especially remote or dial-up clients, often are not. If the client can reach the server and the server can reach the KDC, IAKerb bridges the two.

![](/assets/img/2026-08-05-IAKerb_Research/iakerb_message_relay_flow.png)

## On the wire

IAKerb is a GSS-API mechanism, negotiated through SPNEGO, with the mechanism OID `1.3.6.1.5.2.5`. It wraps standard Kerberos exchanges inside IAKERB tokens. Each token carries a header that names the target realm and an optional cookie the acceptor can use to hold state.

The flow has two optional phases and one mandatory phase. The first optional phase carries the AS exchange, so the client can obtain a TGT through the relay. The second optional phase carries the TGS exchange for a service ticket. The mandatory phase is the ordinary AP exchange that authenticates the client to the server. A client that already holds a TGT can skip the AS phase, and a client that already holds the service ticket can skip the TGS phase.

The important design property is that the KDC never learns about IAKerb. The acceptor unwraps the IAKERB token and forwards a normal AS-REQ or TGS-REQ to the KDC, and the KDC answers as it always would. Once the context completes, the initiator is handed a native Kerberos context. Nothing in the KDC or the base Kerberos mechanism has to be taught about IAKerb for this to work.

One consequence follows from the inversion. Because the server is the machine sending requests to the KDC, the client leaves its own addresses out of the KDC requests. The address fields in the AS and TGS requests are blank, and the address field in the resulting ticket is blank as well. A KDC that saw a forwarded request stamped with the client's address might reject it as coming from the wrong host, and a client that has not yet been assigned an address could not fill the field in anyway.

## Following one exchange

It helps to trace a single logon. A client wants to reach a file server, and it has no path to a domain controller.

The client and server begin a SPNEGO negotiation over the connection they already have, and IAKerb is offered as one of the mechanisms. The client selects it because it has determined it cannot reach a KDC on its own. It builds an AS-REQ, wraps it in an IAKERB token that names the target realm, and sends it to the server. The server unwraps the token, forwards a plain AS-REQ to the KDC, receives the AS-REP, wraps it again, and hands it back. The client now holds a TGT it obtained without ever speaking to the KDC.

The client repeats the pattern for the service ticket. It builds a TGS-REQ for the file server's SPN, wraps it, and the server relays it to the KDC and returns the TGS-REP. With the service ticket in hand the client runs the final AP exchange against the server directly, and authentication completes. If the client had arrived already holding a TGT, the AS round trip would have been skipped, and a cached service ticket would have skipped the TGS round trip as well.

## Finding the realm

There is a small piece of setup hiding in that flow. Before the client can name the realm in its IAKERB tokens, it has to know what that realm is. IAKerb handles this with a proxy message. The client asks, and the acceptor answers with its own realm, since an acceptor is always associated with one. The client then uses that realm to resolve enterprise principal names and to address the rest of the exchange.

## Cross-realm and referrals

IAKerb leans on referrals to cross realm boundaries. When the target lives in a different realm, the KDC has to be able to refer the request along, and the relayed exchange follows those referrals the same way a direct client would. This is why the mechanism assumes a reasonably modern KDC. Referral support is table stakes for it, and an implementation without it is limited to the single-realm case.

## The binding that keeps the relay honest

Relaying authentication messages through a third party invites tampering, so IAKerb binds the conversation. The authenticator subkey is mandatory, and the GSS authenticator carries a finished checksum, a `GSS_EXTS_FINISHED` extension whose data is the DER encoding of a `KRB-FINISHED` structure computed over the IAKERB exchange.

This finished checksum is the integrity anchor. It ties the final AP exchange back to the specific sequence of relayed KDC messages, so a relay that altered the wrapped traffic cannot pass the check. When I start comparing implementations, how strictly each one produces and verifies this binding is one of the first things I want to measure.

## IAKerb is not the KDC Proxy

There is a conflation worth clearing up, because I have seen current reporting mix the two. IAKerb is not the Kerberos KDC Proxy, MS-KKDCP.

KDC Proxy tunnels Kerberos traffic over HTTPS to a dedicated proxy service that sits in front of the KDC. IAKerb has no dedicated proxy. It uses the application server you are already authenticating to as the relay, over the connection you already have to it, such as SMB. The two solve overlapping problems but they are different specifications with different components and different trust models. If you are reasoning about the attack surface, do not treat them as the same thing.

## What the domain controller sees

The role inversion has a consequence I care about for detection. The KDC does not receive the AS-REQ or TGS-REQ from the client. It receives them from the relay server, because the relay is the machine that actually contacts the KDC. The client's own address is absent from the requests by design, as covered above.

So the origin of the Kerberos traffic on the wire is the relay, not the user's machine. Any detection logic that assumes the requesting host is the authenticating principal's host has to account for that. Whether a domain controller can tell an IAKerb-proxied request apart from an ordinary one, and whether the relay is recorded anywhere an analyst would look, is exactly the kind of visibility question I want to measure rather than assume. I will come back to it with captures once the matrix work is underway.

## Where it stands today

IAKerb is an IETF draft, not a Windows invention. MIT Kerberos has carried an IAKERB GSS mechanism for years, implemented as a distinct mechanism layered on the Kerberos mechanism so it can share everything except the context handling.

Windows is now shipping IAKerb as part of the effort to remove NTLM. In the June 2026 Insider preview it is enabled by default, and the client invokes it automatically when it cannot reach a domain controller directly. In the Windows model the application server acts as the relay over the existing application connection, which is exactly the shape the specification describes.

## Why I am looking at this

A new negotiation path and a new relay role mean new decision code and a new trust boundary, and that is the kind of surface I like to characterize before it is everywhere. The questions I want answered are concrete. How does a client decide to choose IAKerb, and can that decision be steered or forced. How strictly does each implementation enforce the finished binding and the rules about which credentials an acceptor will use. What does the relay path mean for how tickets are requested and handled.

I am starting on the reference implementations rather than waiting for Windows to ship broadly, so that when it does I am comparing against a baseline I already understand. The next post is the mechanism side by side across stacks, with captures. This one is just the map.
