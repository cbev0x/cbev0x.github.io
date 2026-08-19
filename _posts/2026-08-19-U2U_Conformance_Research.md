---
title: "User-to-User Kerberos, Acceptor-Side: A Cross-Stack Characterization"
date: 2026-08-19
categories: [Personal, Research]
tags: [Windows, Active Directory, Kerberos, Samba, MIT-krb5, U2U, Heimdal, Research]
published: true
---

## Why U2U, and why the acceptor side

User-to-User (U2U) is the corner of Kerberos where a service has no long-term key of its own, so instead of the client encrypting a service ticket under the server's key, the KDC encrypts it under the session key of a TGT the server volunteers. The request-side story is well covered. Sapphire tickets, UnPAC-the-hash, SPN-less targeted Kerberoast and RBCD, and the `ENC-TKT-IN-SKEY` detection angle are all published, and the real-world trigger for U2U in the wild is understood to be RDP with NLA and CredSSP.

What I could not find covered was the acceptor side, and covered *across implementations*. When a U2U AP-REQ lands on a server, what does that server actually check, and does the answer change between MIT krb5, Heimdal, Windows SSPI, and Samba's vendored Heimdal? The thesis I set out to test was one sentence: the server shares its TGT with the client, but the client cannot decrypt that TGT, so it cannot recover the session key, so it cannot impersonate the server. Every angle below is a test of whether that sentence holds on a given stack.

I will say the conclusion up front, because the honest headline of this work is a negative. The mainstream U2U surface is conformant. I seeded roughly six divergence predictions from a source read and all six collapsed to clean negatives under empirical test. The value here is a rigorous cross-stack characterization rather than a vulnerability, plus a small bundle of MIT-only conformance quirks that are worth a low-severity note upstream.

## Background: the mechanics that matter

Three facts about how a U2U service ticket is built drive everything downstream.

The issued U2U service ticket is encrypted under the *additional* TGT's session key, not under any long-term key. In MIT that is `do_tgs_req.c` taking the ticket-encrypting key from the second ticket's `enc_part2->session`; Heimdal does the same with the additional-ticket session key. The enctype of that session key was chosen by the KDC back at AS time, so on an AES domain the U2U ticket rides on AES.

The client names itself in the request, and the issued ticket's `cname` is the requestor. That matters for the cross-realm case, because it means a foreign requestor's identity is what gets carried into the ticket the target-realm KDC issues.

And the additional ticket has to be a TGT. The KDC does not decrypt an arbitrary service ticket into the session-key slot; there is a policy gate that requires the additional ticket to be a ticket-granting ticket for the local realm. That gate turns out to be the first of several predictions I got wrong, so it is worth looking at closely.

## Acceptor-side: reading the source first

I started static, with shallow clones of MIT and Heimdal and the `samba-4.24.0` tag of Samba's vendored Heimdal.

The first result is a clean scoping win. Neither MIT nor Heimdal exposes a U2U *acceptor* mechanism through GSS-API. MIT's `accept_sec_context.c` never arms a user-to-user key; it only ever reads subkeys. Heimdal's acquire-cred path returns failure for the accept-side credential store U2U would need, with a comment stating outright that U2U needs an extension allowing more than two context tokens that Heimdal does not implement, and its accept path is keytab-only. The practical consequence is sharp: portable GSS services built on MIT or Heimdal, so SSH with GSSAPI, Postgres and MSSQL GSSAPI, NFSv4 with krb5, Hadoop, cannot be U2U acceptors. The "server volunteers its TGT" primitive is specific to Windows SSPI at the application layer. It is not a portable-GSS behavior.

Below GSS, the raw `krb5_rd_req` path does support acceptor U2U, and here the source appeared to show a real divergence. MIT's `rd_req_dec.c` selects the U2U branch solely on whether the application armed a user-to-user key, and the client's `USE-SESSION-KEY` AP option is not consulted. The check for it is literally a commented-out `if`. Heimdal's `rd_req.c` looked stricter: it appeared to require both the incoming AP-REQ's `use_session_key` option set *and* a keyblock present, and it has an explicit `KRB5KRB_AP_ERR_NOKEY` path for "user to user auth without session key given." Samba's vendored copy was byte-identical to upstream Heimdal at the relevant line.

So the static read said: the U2U-decrypt trigger is client-flag-driven on Heimdal and Samba, but local-application-state-driven on MIT. That is a genuine-looking behavioral fork, and it is wrong. I will come back to why the dynamic test overturned it, because the reason it is wrong is more interesting than the prediction.

## The dynamic battery

I built a small harness of raw `krb5_rd_req` acceptors and matching clients in C, one pair for MIT and one for Heimdal, with a flag argument on the client to toggle `AP_OPTS_USE_SESSION_KEY` on or off independently of everything else. The full code is at the end of this post. The lab is a real Windows domain (`reflect.lab`, Server 2025), a source-built Samba AD DC (`samba.lab`, Samba 4.24), and MIT krb5 1.20.1 on Kali, with a two-way forest trust between the two domains.

### The flag is decorative once a key is armed

The prediction was that Heimdal would reject a U2U ticket sent with the flag *off*, and MIT would accept it, because the source showed Heimdal gating on the flag. Both accepted it either way. MIT accepted flag on and flag off; Heimdal accepted flag on and flag off.

The root cause is a line I missed in the static pass. Heimdal's `krb5_rd_req_ctx` copies the armed keyblock into its output context unconditionally whenever a key is present, with no flag check, and then hands that keyblock to the verify path as the fallback decrypt key. So flag-on uses the auth-context key and flag-off uses the copied keyblock, and both are the same session key. The flag never gates the decrypt once a key is armed. It only has teeth in the no-key case, where the flag is set but no key was ever armed, which yields the `NOKEY` error. MIT is structurally identical. The lesson I took from this is the ordinary one: the interesting control was three functions away from the branch I was reading, and only the dynamic test surfaced it.

This is benign. Without an armed key, an `ENC-TKT-IN-SKEY` ticket falls through to the keytab path and fails to decrypt, so a client cannot *force* U2U onto a server that is not expecting it. The flag being decorative does not open a door; it just means the door was never where the source made it look.

### The additional ticket must be a TGT, and MIT is stricter about it

I fired a U2U request with a service ticket, not a TGT, in the additional-ticket slot. Both KDCs rejected it. On MIT the rejection is a policy-module decision, not a decryption failure: `check_tgs_u2u` requires the additional ticket's server to be the local TGS and requires the additional ticket's client to equal the requested U2U server. Heimdal enforces the TGT requirement through a realm check that is looser than MIT's client-equality constraint. Both reject a non-TGT. No finding, but a clean characterization of where each stack draws the line.

MIT also explicitly rejects the combination of `ENC-TKT-IN-SKEY` and the S4U2Proxy option bits set together, returning a bad-option error, which closes a U2U-versus-delegation confusion from the source. Heimdal does not check the both-bits case, though nothing downstream made it exploitable.

### Cross-realm U2U works, and Windows carries the foreign PAC through

Cross-realm U2U functions. A requestor in one realm can U2U to a target in another, the referral chain resolves at the target's home KDC where the target's TGT is a local TGS, and the foreign client identity rides through into the issued ticket.

The part worth dwelling on is what Windows does with the PAC. When the Windows KDC issues a U2U ticket to a foreign requestor, it copies that requestor's foreign identity through verbatim and re-endorses it with its own realm's checksums. In my capture the issued ticket's PAC kept the foreign domain SID intact, the foreign RID, the foreign group membership, and a full modern buffer set. Windows does not reduce a foreign U2U requestor's PAC to nothing. That copy-through is exactly the shape a cross-realm injection would need to exploit, so it is worth naming as a substrate even though, as the next section shows, the door it might open is closed elsewhere.

### One behavior worth flagging for defenders

In a U2U service ticket the PAC's server checksum and ticket checksum are keyed by the target's TGT session key, the U2U service key, rather than by a long-term key. Anyone holding a target's TGT session key can therefore forge a PAC that passes those two checksums for U2U tickets to that target. Only the KDC-keyed checksums stay out of reach. This reduces to a known silver-ticket-class observation rather than a new break, since holding a TGT's session key is close to controlling the TGT, but it is the cleanest way to state where the trust actually sits in a U2U ticket.

The offensive framing that falls out of all this: U2U turns any TGT holder into a Kerberos authentication target with no SPN, which is a quiet acceptor whose only telemetry is a comparatively rare `4769` with `ENC-TKT-IN-SKEY`, and a rogue U2U server harvests the caller's PAC inside a ticket it can actually decrypt, which is UnPAC-the-hash turned outward. A rogue RDP-NLA endpoint is the natural vector. None of this is novel, and prior work has already established that no-SPN U2U PAC harvesting is uncommon in practice and that the recon it enables is available through LDAP anyway.

## SID filtering: the one place a cross-realm bug could have lived

Given that Windows copies a foreign requestor's PAC through, the obvious question is whether cross-forest SID filtering is applied on the U2U path the same way it is on the normal path. If U2U skipped filtering, injecting a high-privilege SID from a compromised trusted forest would be a real finding.

It does not skip it. I forged a referral TGT with a foreign forest's Domain Admins SID injected using the inter-realm key, then delivered it two ways: the normal path via `kvno` for a service, and the U2U path through my client. The injected SID was stripped in both, with byte-identical resulting PACs. Windows applies cross-forest SID filtering uniformly, at incoming-referral-PAC processing, which sits before the U2U branch, so U2U is not a bypass. As the Windows-versus-Samba symmetry leg: Windows filters, and Samba applies no forest-trust SID filtering at all, which is a documented Samba limitation rather than a bug.

## Armoring: does mandatory FAST reach the U2U exchange

FAST armoring and U2U coexist at the mechanics level. An armored requestor TGT does U2U normally. The security-relevant question is whether a domain that mandates Kerberos armoring, the Windows "fail unarmored authentication requests" posture, actually enforces armoring on the U2U exchange, or whether U2U slips through as an enforcement hole.

I enabled fail-unarmored on the domain controller, confirmed a normal unarmored AS-REQ was rejected with a policy error, and then captured a genuine native U2U exchange on the wire. The native Windows client FAST-wraps its U2U TGS-REQ exactly like any other TGS-REQ. The request carried `PA-FX-FAST`, the additional ticket was present with `enc-tkt-in-skey` set, and the KDC issued the ticket. There is no unarmored-U2U hole on the native path.

Two supporting observations came out of trying to test the unarmored case deliberately. MIT auto-arms its TGS-REQ whenever the realm advertises FAST and it has a usable armor source, so it will not emit an unarmored U2U request to an enforcing KDC even when you try to make it. And the enforcement decision the KDC makes on an unarmored TGS-REQ under fail-unarmored is upstream of the U2U mechanics, so the `enc-tkt-in-skey` flag does not change it. The practical picture is that neither the native Windows client nor MIT hands an enforcing KDC an unarmored U2U request in the first place.

## MIT-only conformance quirks

Three small divergences are MIT-only, all fail-closed or low-impact, and collectively they are the closest thing to a positive finding in this work. None is a vulnerability; together they are a reasonable upstream conformance note.

MIT accepts a postdated additional ticket. It will issue a postdated, still-invalid TGT and then accept that same TGT as a U2U additional ticket without checking its not-valid-yet state. Samba refuses to issue a postdated TGT at all, so the question never arises there, and Windows has no postdated support to begin with.

MIT accepts an *expired* additional ticket. I gave a principal a three-second TGT, waited, confirmed the ticket was genuinely dead on the normal path with a ticket-expired error, then used that same dead ticket as a U2U additional ticket. MIT issued the U2U service ticket. Samba rejects the same case with a ticket-expired error. So MIT does not check the additional ticket's temporal validity in either direction. The honest impact is low, because the additional ticket is the target's own TGT and its session key is valid cryptographic material regardless of the stated lifetime, but it is a clean conformance gap.

MIT blocks U2U to a target whose account requires preauthentication, where Windows and Samba both allow it. This is over-strict rather than dangerous. `requires_preauth` is an AS-REQ gate, but MIT's `check_tgs_u2u` validates the U2U target as though it were a client and applies the preauth-required check even though the target already holds a TGT and no AS-REQ is happening. I confirmed it was the target's flag and not the requestor's by moving the flag between the two accounts, and confirmed it was reversible. MIT fails closed here, so there is no security consequence, but it is a behavioral outlier worth documenting.

## Enctype

Every U2U service ticket session key I observed, Samba-issued, Windows-issued cross-realm, and local MIT, was AES256. That is the expected result on AES-capable domains, since the session key enctype is fixed by the KDC at AS time.

There is a published SPN-less RBCD-via-U2U chain that is often described as depending on RC4. If that chain does have a hard RC4 dependency, then an AES-only domain would break it, since the U2U ticket rides on the session key enctype the KDC chose and that is AES here. I want to be careful with this claim rather than overstate it: the solid empirical fact is that the U2U ticket session key is AES on a modern domain, and the chain-break is a plausible consequence that depends on the exact RC4 dependency in the prior-art chain. I would confirm that dependency against the original source before relying on it operationally.

## Interoperability

The MIT and Heimdal clients and acceptors are fully wire-interoperable in both directions. A Heimdal client to an MIT acceptor accepts, and an MIT client to a Heimdal acceptor accepts. The Windows-client-to-Linux-acceptor leg I established by composition rather than a single direct capture: I captured a well-formed native Windows U2U request and AP-REQ that the KDC accepted, and separately showed that Linux `krb5_rd_req` acceptors validate U2U AP-REQs from both Linux stacks, so the remaining seam is only the Windows-origin bytes reaching a Linux acceptor, which the wire format all but guarantees.

## The harness

Everything above runs on a small, deliberately minimal C harness: raw `krb5_rd_req` acceptors and clients with no GSS wrapping, so the U2U mechanics are exposed directly. Below are the two core pieces. A shared `u2u_net.h` provides length-prefixed `send_msg`/`recv_msg`/`tcp_connect`/`tcp_listen` helpers over a socket; it is a straightforward 4-byte-length framing wrapper and is omitted here for space, but it is in the repo.

### The acceptor

The acceptor arms the target principal's TGT session key with `krb5_auth_con_setuseruserkey`, then calls `krb5_rd_req`. That one call is the whole U2U acceptor: arming the key is what selects the session-key decrypt path.

```c
/* u2u_acceptor_mit.c - raw krb5_rd_req U2U acceptor.
 * Arms the volunteered TGT session key, sends the TGT ticket to the client,
 * then reads and validates the client's U2U AP-REQ. Set U2U_PAC_DUMP=<file>
 * to write the decoded authorization data for offline PAC inspection.
 */
#include <krb5.h>
#include "u2u_net.h"

static void bail(krb5_context ctx, krb5_error_code code, const char *msg) {
    if (ctx) { const char *e = krb5_get_error_message(ctx, code);
               fprintf(stderr, "FATAL %s: %s (%ld)\n", msg, e, (long)code);
               krb5_free_error_message(ctx, e); }
    else fprintf(stderr, "FATAL %s (%ld)\n", msg, (long)code);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 1; }
    int port = atoi(argv[1]);

    krb5_context ctx; krb5_error_code r;
    if ((r = krb5_init_context(&ctx))) bail(NULL, r, "init_context");

    /* our own credentials cache holds the TGT we will volunteer */
    krb5_ccache cc; if ((r = krb5_cc_default(ctx, &cc))) bail(ctx, r, "cc_default");
    krb5_principal me; if ((r = krb5_cc_get_principal(ctx, cc, &me))) bail(ctx, r, "cc_get_principal");

    /* fetch our own TGT (krbtgt/REALM@REALM) so we can hand its ticket to the client */
    krb5_principal tgtsrv;
    const krb5_data *realm = krb5_princ_realm(ctx, me);
    if ((r = krb5_build_principal_ext(ctx, &tgtsrv,
             realm->length, realm->data,
             6, "krbtgt",
             realm->length, realm->data, 0)))
        bail(ctx, r, "build krbtgt");

    krb5_creds mcred, *tgt = NULL;
    memset(&mcred, 0, sizeof(mcred));
    mcred.client = me; mcred.server = tgtsrv;
    if ((r = krb5_get_credentials(ctx, 0, cc, &mcred, &tgt)))
        bail(ctx, r, "get own TGT");

    int lfd = tcp_listen(port);
    if (lfd < 0) { fprintf(stderr, "listen failed\n"); return 2; }
    fprintf(stderr, "[acceptor] listening on %d as ", port);
    { char *n; krb5_unparse_name(ctx, me, &n); fprintf(stderr, "%s\n", n); krb5_free_unparsed_name(ctx, n); }

    for (;;) {
        int fd = tcp_accept(lfd);
        if (fd < 0) continue;

        /* (0) volunteer our TGT ticket to the client - this is the U2U handshake */
        if (send_msg(fd, tgt->ticket.data, tgt->ticket.length) < 0) { close(fd); continue; }

        /* (1) receive the client's U2U AP-REQ */
        void *apbuf; uint32_t aplen;
        if (recv_msg(fd, &apbuf, &aplen) < 0) { close(fd); continue; }

        /* (2) arm the TGT session key: THIS selects the U2U decrypt path */
        krb5_auth_context ac = NULL; krb5_auth_con_init(ctx, &ac);
        if ((r = krb5_auth_con_setuseruserkey(ctx, ac, &tgt->keyblock))) {
            fprintf(stderr, "[acceptor] setuseruserkey: %ld\n", (long)r);
            free(apbuf); krb5_auth_con_free(ctx, ac); close(fd); continue;
        }

        /* (3) validate the AP-REQ */
        krb5_data apreq = { .length = aplen, .data = apbuf };
        krb5_ticket *tkt = NULL;
        r = krb5_rd_req(ctx, &ac, &apreq, NULL /* server = from ticket */, NULL, NULL, &tkt);

        const char *verdict;
        if (r == 0) {
            verdict = "ACCEPT";
            /* optional: dump the decoded authorization data (PAC) for inspection */
            char *pacfile = getenv("U2U_PAC_DUMP");
            if (pacfile && tkt && tkt->enc_part2 && tkt->enc_part2->authorization_data)
                dump_authdata(pacfile, tkt->enc_part2->authorization_data); /* helper in repo */
        } else {
            verdict = krb5_get_error_message(ctx, r);
        }
        fprintf(stderr, "[acceptor] verdict: %s (%ld)\n", verdict, (long)r);
        send_msg(fd, verdict, strlen(verdict));

        if (tkt) krb5_free_ticket(ctx, tkt);
        krb5_auth_con_free(ctx, ac);
        free(apbuf);
        close(fd);
    }
}
```

### The client

The client receives the acceptor's volunteered TGT ticket, requests a U2U service ticket with `KRB5_GC_USER_USER` (which sets `ENC-TKT-IN-SKEY` and carries the received TGT as the additional ticket), then builds the AP-REQ with the session-key option toggled by a flag so the flag's effect can be tested in isolation.

```c
/* u2u_client_mit.c - MIT U2U client with a USE-SESSION-KEY flag toggle.
 * flag=1 correct U2U (session-key ticket + AP option set)
 * flag=0 same session-key ticket sent WITHOUT the option, to test whether
 *        the acceptor gates the decrypt on the client's flag (it does not).
 */
#include <krb5.h>
#include "u2u_net.h"

static void bail(krb5_context ctx, krb5_error_code code, const char *msg) {
    if (ctx) { const char *e = krb5_get_error_message(ctx, code);
               fprintf(stderr, "FATAL %s: %s (%ld)\n", msg, e, (long)code);
               krb5_free_error_message(ctx, e); }
    else fprintf(stderr, "FATAL %s (%ld)\n", msg, (long)code);
    exit(2);
}

int main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: %s <host> <port> <target_princ> <flag 0|1>\n", argv[0]); return 1; }
    const char *host = argv[1]; int port = atoi(argv[2]);
    const char *target = argv[3]; int flag = atoi(argv[4]);

    krb5_context ctx; krb5_error_code r;
    if ((r = krb5_init_context(&ctx))) bail(NULL, r, "init_context");
    krb5_ccache cc; if ((r = krb5_cc_default(ctx, &cc))) bail(ctx, r, "cc_default");
    krb5_principal me; if ((r = krb5_cc_get_principal(ctx, cc, &me))) bail(ctx, r, "cc_get_principal");
    krb5_principal tprinc; if ((r = krb5_parse_name(ctx, target, &tprinc))) bail(ctx, r, "parse target");

    int fd = tcp_connect(host, port);
    if (fd < 0) { fprintf(stderr, "connect failed\n"); return 2; }

    /* (0) receive the target's TGT ticket = the U2U additional ticket */
    void *tkbuf; uint32_t tklen;
    if (recv_msg(fd, &tkbuf, &tklen) < 0) { fprintf(stderr, "recv target TGT failed\n"); return 2; }
    fprintf(stderr, "[client] received target TGT ticket, len=%u\n", tklen);

    /* (1) request the U2U service ticket: GC_USER_USER sets ENC-TKT-IN-SKEY and
     *     carries the received TGT as the additional (second) ticket */
    krb5_creds in_creds, *out_creds = NULL;
    memset(&in_creds, 0, sizeof(in_creds));
    in_creds.client = me;
    in_creds.server = tprinc;
    in_creds.second_ticket.data = (char *)tkbuf;
    in_creds.second_ticket.length = tklen;
    if ((r = krb5_get_credentials(ctx, KRB5_GC_USER_USER, cc, &in_creds, &out_creds)))
        bail(ctx, r, "get_credentials(GC_USER_USER)");
    fprintf(stderr, "[client] got U2U ST: session enctype=%d\n", out_creds->keyblock.enctype);

    /* (2) build the AP-REQ, toggling AP_OPTS_USE_SESSION_KEY by <flag> */
    krb5_auth_context ac = NULL; krb5_auth_con_init(ctx, &ac);
    krb5_flags apopts = flag ? AP_OPTS_USE_SESSION_KEY : 0;
    krb5_data apreq; memset(&apreq, 0, sizeof(apreq));
    if ((r = krb5_mk_req_extended(ctx, &ac, apopts, NULL, out_creds, &apreq)))
        bail(ctx, r, "mk_req_extended");
    fprintf(stderr, "[client] AP-REQ built (flag=%d, len=%d)\n", flag, apreq.length);

    if (send_msg(fd, apreq.data, apreq.length) < 0) { fprintf(stderr, "send failed\n"); return 2; }

    /* (3) read the acceptor's verdict */
    void *vbuf; uint32_t vlen;
    if (recv_msg(fd, &vbuf, &vlen) == 0) {
        printf("[client] acceptor said: %.*s\n", (int)vlen, (char *)vbuf);
        free(vbuf);
    }
    close(fd);
    return 0;
}
```

Build against MIT with `gcc -O2 -o u2u_acceptor_mit u2u_acceptor_mit.c -lkrb5`. The Heimdal variants are the same source with the session keytype read adjusted for Heimdal's `krb5_creds` layout, built with `gcc -O2 -o u2u_acceptor_heimdal u2u_acceptor_heimdal.c -I/usr/include/heimdal -L/usr/lib/x86_64-linux-gnu/heimdal -lkrb5`.

To run a full U2U exchange: `kinit` as the target principal, start the acceptor on a port, then from a client cache run `u2u_client_mit <host> <port> <target>@<REALM> 1`. Flip the trailing flag to `0` to confirm for yourself that the acceptor still accepts, which is the keyblock-copy behavior described above.

## Closing

The mainstream U2U acceptor surface holds up. Across MIT, Heimdal, Windows, and Samba the decrypt path behaves the way the specification implies once you account for the keyblock-copy that makes the client flag decorative, the additional-ticket-must-be-a-TGT gate, uniform cross-forest SID filtering on Windows, and armoring that reaches the U2U exchange rather than being bypassed by it. The divergences that survive are MIT-only, fail-closed, and low-impact: lax temporal validation of the additional ticket, and an over-strict preauth check on the U2U target. Those are worth an upstream conformance note, not an advisory.

I went in expecting to find a seam and came out with a characterization. That is a fair outcome for this kind of work, and the negative is itself useful: if you are reasoning about U2U in a mixed environment, the acceptor side is not where the surprises live.
