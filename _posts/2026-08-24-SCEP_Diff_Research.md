---
title: "Five SCEP Servers, One Harness: A Cross-Implementation Differential"
date: 2026-08-24
categories: [Personal, Research]
tags: [Windows, Active Directory, AD CS, SCEP, Enrollment, Research]
published: true
---

SCEP is the protocol that quietly issues a large share of the certificates on a modern network. Every MDM-enrolled phone, every Intune or Jamf device, and every Windows box that talks to NDES walks through the same handful of message types: `GetCACaps`, `GetCACert`, `PKCSReq`, `GetCertInitial`, `GetCert`, `RenewalReq`. The spec is old, the deployments are everywhere, and the client tooling is mostly vendor-specific black boxes. That combination is exactly where I expected divergence to live.

The usual way people look at SCEP is one server at a time: point a client at NDES, see what it does, move on. I wanted the opposite. I stood up five independent SCEP server implementations on one bench and drove all of them from a single harness I wrote, so that every message I sent hit five different codebases at once and I could read the differences directly. Divergence between implementations is where interop breaks, and it is also where security assumptions stop holding, because a message one server treats as invalid is a message another server might act on.

This post is the result of that work: the harness, the five-way baseline, and the full set of offensive probes I ran against it. I will say up front that I did not find a novel remotely-exploitable vulnerability. What I found is a precise map of where these implementations agree, where they diverge, and where the divergences stop short of being exploitable. The map, and the tool that produced it, are the contribution.

## The bench

Five servers, each a distinct implementation, each issuing end-to-end before I sent a single malformed byte:

| Host | Implementation | Notes |
|---|---|---|
| NDES01 | Microsoft NDES (Windows Server 2025) | native `mscep.dll` ISAPI, AD-integrated, domain-issued OTP challenge |
| ejbca01 | EJBCA Community Edition | Java, pre-registered end entity + password |
| dogtag01 | Dogtag PKI (standalone) | Java/Tomcat, flatfile PIN bound to client IP |
| openxpki01 | OpenXPKI | Perl, two-tier CA, workflow-driven |
| microscep01 | micromdm/scep | Go reference server, static challenge |

The client side is a tool I wrote called SCEPMutator. I did not use an off-the-shelf SCEP client because I needed to forge messages that a conforming client would never produce: mismatched signer keys, broken proof-of-possession, hand-crafted PKCS#1 padding, and so on. SCEPMutator builds the full stack itself, from the PKCS#10 up through the CMS `EnvelopedData` and `SignedData` with the SCEP authenticated attributes, and it auto-adapts transport and algorithms from each server's advertised capabilities. That last part matters more than it sounds: the five servers advertise five different capability sets, use five different challenge models, and two of them return `GetCACert` bundles that are not even strict DER.

A SCEP `PKCSReq` is a nested structure, and each layer is a separate thing a server can check or fail to check. This is the map I attacked against:

![](/assets/img/2026-08-24-scep_research/scep_diagram.png)

Every probe in this project targets one of those layers: the outer signature, the signer certificate, the RSA-wrapped key, or the inner CSR's subject, key, and self-signature. The security of SCEP enrollment comes down to which of these a given server actually validates.

## The baseline nobody publishes

Before any attack, I froze a baseline: capabilities, CA-certificate bundle shape, challenge model, and transport, for each server. Five servers produced five distinct fingerprints. No two were identical, and only DES3 plus SHA-256 were universal.

| | NDES | EJBCA | Dogtag | OpenXPKI | micromdm |
|---|---|---|---|---|---|
| Advertises SHA-1 | yes | yes | no | yes | yes |
| `POSTPKIOperation` | yes | yes | no (GET+base64) | yes | yes |
| `GetCACert` bundle | 3-cert, BER | 1-cert | 1-cert | 2-cert, BER | 1-cert |
| Challenge model | domain OTP, single-use | pre-reg EE + password | flatfile PIN, IP-bound | fixed, CN-scoped | static string |
| Reply cipher | matches request | matches request | matches request | matches request | forced single-DES |

The first surprises came from the conformant path, before I sent anything malformed.

NDES and OpenXPKI both return multi-certificate `GetCACert` bundles whose `SignedData.certificates` SET is not in DER order. A strict-DER parser rejects both and has to fall back to BER. Two independent implementations, one written in C for Windows and one in Perl, share the same deviation. The three single-certificate servers are clean, because there is no SET to misorder. A strict-DER SCEP client cannot consume either bundle without a fallback, which is a real interop finding hiding in plain sight.

micromdm has its own set of quirks on the reply path. It envelopes its `CertRep` with single 56-bit DES regardless of what cipher I requested, so I asked for AES-256 and got DES back. It also encodes the encrypted content as a constructed, BER-segmented OCTET STRING where the other four use primitive DER. Neither is exploitable, but both broke my parser until I handled them, and both are the kind of thing that only shows up when you decode the reply by hand instead of trusting a client library.

NDES has a roughly twelve-second cold-start on the first `GetCACaps` after the CA becomes reachable, then settles to about four milliseconds warm. That is lazy CA-context initialization, and it is a timing signal, though not one I could turn into anything.

## The identity triangle: does the server check who is asking

SCEP's `PKCSReq` carries a proof-of-possession in two places. The inner PKCS#10 is self-signed by the key being certified. The outer CMS is signed by an ephemeral certificate whose key is supposed to match. The whole security question of SCEP enrollment is whether the server actually checks that binding, or whether it trusts the challenge password and waves the rest through.

I broke each binding independently. First I signed the outer CMS with a key that did not match the enclosed signer certificate. Then I submitted an inner PKCS#10 carrying a public key I did not control, with an invalid self-signature.

The outer-signature mutation produced the most interesting divergence of the whole project. NDES rejected it cleanly with `badMessageCheck`. OpenXPKI returned HTTP 400. Dogtag threw an uncaught exception and returned HTTP 500. micromdm errored. EJBCA issued a certificate.

| Server | outer CMS signature enforced | inner CSR proof-of-possession enforced | on violation |
|---|---|---|---|
| NDES | yes | yes | clean SCEP `FAILURE` |
| EJBCA | no | yes | outer: issues; inner: `400`, log says `POPO verification failed` |
| OpenXPKI | yes | yes | HTTP 400 |
| Dogtag | crashes | crashes | HTTP 500 (uncaught exception) |
| micromdm | crashes | no | outer: 500; inner: **issues** |

For about thirty seconds that looked like a finding. EJBCA had accepted a request whose outer CMS signature did not verify against the enclosed certificate. But the follow-up test is what separates a conformance gap from a vulnerability, and it deflated it: when I broke the inner PKCS#10 proof-of-possession instead, EJBCA rejected it, and its log said so explicitly with `POPO verification failed`. EJBCA does not enforce the outer SCEP signature, but it does verify the inner CSR self-signature, and it still requires the challenge. So the outer-signature gap is a conformance divergence from RFC 8894, not an exploitable one. The requester still has to prove possession of the key being certified and still has to know the challenge.

micromdm was the one server that issued on the broken inner proof-of-possession. That is a real gap, but it gates out on prior art: micromdm's own documentation makes CSR verification an opt-in external hook that is off by default, and the broader weakness (SCEP authenticates a shared secret, not the requesting entity) is CERT/CC VU#971035. It is a reference implementation behaving as documented, not a new bug.

So the identity triangle resolved to no vulnerability, but I proved it four different ways rather than assuming it, and I caught myself before calling the EJBCA outer-signature gap a finding. That pattern, an interesting-looking result that dissolves under the second test, repeated for the rest of the project.

## Renewal, and why cross-CA confusion does not apply

SCEP renewal drops the challenge and authenticates purely by signing the request with an existing certificate's key. That makes the interesting question obvious: does a server verify that the renewal certificate was issued by itself, or will it accept a certificate a different CA issued?

Two things had to be true before that test meant anything. First, the renewal had to actually work, and it took a tool fix to get there: all five servers reject the RFC 8894 `RenewalReq` message type (17), and the interoperable method is a `PKCSReq` (19) signed by the existing certificate. Second, the same-CA baseline had to succeed, or a cross-CA rejection would prove nothing.

Once renewal worked, the cross-fire was clean. I renewed NDES with an OpenXPKI-issued certificate, and NDES rejected it. NDES binds renewal to certificates that chain to its own trust, which is what a mature CA is supposed to do. Cross-CA renewal confusion does not apply, and on reflection it cannot, because "renewal" means "renew a certificate I issued" and every serious implementation ties it to its own issuance records. This was the probe I was most optimistic about going in, and the architecture closed it.

## Fuzzing the parsers, and an inverted assumption

I threw two malformation corpora at every server. The first was the usual byte-level work on the CMS body: truncation, length overflow and underflow, deep nesting, indefinite-length BER, trailing garbage, null injection. The second was a deeper corpus aimed at the places bounds bugs actually live: fifty thousand levels of nesting to exhaust a parser stack, integer-overflow length fields claiming multi-gigabyte structures, a one-megabyte OCTET STRING to stress allocation, and corruption reaching inside the envelope.

Eighteen cases across five servers produced zero crashes, zero hangs, and zero genuine unexpected-accepts.

| Server | malformed-input behavior | stack-trace leak | crash / hang |
|---|---|---|---|
| NDES | clean SCEP `FAILURE`, empty-body on extreme nesting (has a depth guard) | no | none |
| EJBCA | clean HTTP 400 | no | none |
| OpenXPKI | HTTP 500 at the input layer, generic text | no | none |
| micromdm | HTTP 500 (Go error path) | no | none |
| Dogtag | HTTP 500 (uncaught exception) | **yes** (documented) | none |

The result I did not expect was which server was toughest. Going in, I assumed the native `mscep.dll` would be the fragile one, because native ASN.1 parsing has a long history of memory-safety bugs. It was the opposite. NDES handled every malformation without crashing, hanging, or leaking, and it had a nesting depth guard that returned an empty body rather than blowing its stack. EJBCA was equally robust with clean HTTP 400s. The fragile servers were the ones I would have bet on being safe: micromdm, OpenXPKI, and Dogtag all returned uncaught HTTP 500s on malformed input. But they all fail closed, none leaked a stack trace except Dogtag (which is already documented), and none crashed. The native parser being the hardened one is a genuinely counterintuitive result and, I think, the single most interesting line in the differential.

I also had to build discipline into the tool here. A naive fuzzer flags any response that differs from a valid one, and my first pass produced a pile of false positives because a valid enrollment issues a fresh certificate every time, so the response length varies even with no mutation. I fixed it by probing an idempotent operation and confirming a byte-stable baseline before trusting any diff. That fix mattered again later.

## Downgrade, polling, and proxy headers

Three more surfaces, three more clean results, each worth stating because each is a real question.

Downgrade: does a server accept an algorithm it advertises as absent? The answer is that the question mostly does not apply, because four of the five advertise SHA-1 alongside SHA-256 and SHA-512. Accepting SHA-1 is advertised behavior, not a downgrade. The one server that omits SHA-1 from its capabilities, Dogtag, refuses SHA-1. There is no advertised-versus-enforced gap to exploit.

Polling authorization: SCEP's `GetCertInitial` retrieves a certificate by subject, and `GetCert` retrieves one by serial. I enrolled as the legitimate requester, then polled for that certificate signed by an unrelated identity. Every server refused the non-originator poll, and `GetCert` by serial returned my own certificate but refused every neighboring serial. Retrieval is bound to the requester across all five. There is no enumeration primitive.

Proxy-trust headers: the common real-world SCEP deployment puts NDES behind a reverse proxy or an Intune connector, so I asked whether any server trusts headers a proxy would set. I sent thirteen of them, including the IIS client-certificate headers and injected-identity headers, straight at each origin. None changed behavior on any server. SCEP authenticates with the challenge and the CMS signature, not HTTP identity headers, so a proxy in front does not hand an attacker a header-trust bypass. This is where the idempotent-baseline discipline paid off again: my first run flagged all thirteen headers as changing behavior on two servers, and every one of those was the same enrollment-variance artifact, not a real effect.

## The padding oracle, done carefully

SCEP mandates RSA PKCS#1 v1.5 key transport for the content-encryption key. That is the exact mechanism behind twenty-five years of Bleichenbacher and ROBOT vulnerabilities, and nobody had systematically tested SCEP servers for it across implementations. This was the one probe where I thought a real, serious, novel finding was genuinely plausible.

I crafted eight RSA blocks with controlled PKCS#1 v1.5 structure and verified by decryption that each had exactly the plaintext shape I intended: a conformant block, several with invalid padding in different ways, and the critical pair with valid padding but an unusable recovered key. A conforming server must be indistinguishable across all of them. Any difference in status, failInfo, or timing is an oracle.

No server produced a status or failInfo oracle. Each returned a single identical response signature across all eight variants, including the padding-valid-but-key-unusable distinguisher that a vulnerable server would treat differently. NDES, running Windows CNG's constant-time RSA, and EJBCA, on the Java stack, were flat.

Dogtag produced a timing anomaly, and this is where the method mattered most. Two variants were consistently slow across forty repetitions while the other six were fast, and it was reproducible, not jitter. But a padding oracle requires the timing to separate on padding validity, and this did not. The valid-padding-but-wrong-key case, which is the exact distinguisher a Bleichenbacher attack needs, timed with the fast invalid-padding group, not the slow group. The valid-padding class spanned the entire range and straddled the invalid class. So the timing split is real but it tracks some downstream code path, not padding validity, and it gives an attacker no usable signal. I grouped the variants by padding validity and showed the classes do not separate, rather than waving the anomaly away. It is a benign performance quirk, not an oracle.

## Two creative attacks, for completeness

The conformance matrix was done, so I tried two composition attacks that are not in any checklist.

First, I presented the CA's own certificate as the outer CMS signer, so the message would appear to originate from the CA itself, signed with a key I did not hold. The question was whether any server extends trust to a self-originated-looking message. NDES and micromdm rejected it. EJBCA and Dogtag returned success, which looked alarming until I noticed the reply is enveloped to the signer certificate, which is the CA certificate, whose private key I do not hold. The success is uncashable. I can make those servers say yes, but I cannot decrypt the certificate they issue, so the attack yields nothing.

Second, I submitted a CSR whose subject is the CA's own distinguished name, attempting self-issuance. The mature servers refused: EJBCA returned 403, Dogtag returned a SCEP failure. micromdm issued a certificate with the CA's name as its subject, but with basic constraints set to `CA=False`. It is an ordinary end-entity leaf with a cosmetic name collision, not a usable CA certificate, and it is the same "micromdm issues whatever subject you ask for" behavior already covered by prior art. No server issued a `CA=TRUE` certificate to an outside requester, which is the outcome that would have mattered.

## What this adds up to

I ran the full offensive matrix, plus supplementary probes on the request router, the privileged challenge endpoint, retrieval by serial, and concurrency, plus a padding-oracle differential and two composition attacks. Twenty-seven documented results across five implementations. Zero novel remotely-exploitable vulnerabilities. Every interesting behavior either gated to documented prior art or proved non-exploitable when I pushed on it.

| Probe | What it tests | Result |
|---|---|---|
| Identity triangle | outer signature + inner proof-of-possession | no vuln; all verify inner PoP |
| Renewal / cross-CA | renewal trust-binding | no vuln; issuer-bound by design |
| Malformation fuzzing (18 cases) | parser robustness | no crash/hang; native NDES parser most robust |
| Downgrade | advertised vs enforced algorithms | no gap; servers advertise what they accept |
| Polling / GetCert | retrieval authorization | no vuln; requester-bound |
| Proxy-trust headers (13) | header-identity trust | no vuln; none honored |
| Request router | operation and parameter handling | no vuln; characterized |
| mscep_admin endpoint | privileged OTP surface | no vuln; auth enforced |
| Concurrency (10x same-txid) | state-machine race | no vuln; serialized |
| Padding oracle (Bleichenbacher/ROBOT) | PKCS#1 v1.5 decryption | no oracle; timing anomaly proven benign |
| Self-trust / self-issuance | composition attacks | no vuln; uncashable or non-CA leaf |

I want to be honest that this is not the outcome I was hunting for, and also that it is a real result. Verifying that mature SCEP servers correctly handle proof-of-possession, renewal trust-binding, retrieval authorization, downgrade, header trust, malformed-input robustness, concurrency, and PKCS#1 padding is worth something precisely because most people assert it and never test it. Along the way the discipline caught five separate false positives that a faster pass would have shipped as findings: the EJBCA outer-signature gap, the micromdm concurrency race, the getcert own-serial return, the header-injection variance, and the Dogtag padding timing. Retracting those is not a failure of the method, it is the method working.

The lasting outputs are the tool and the map. SCEPMutator forges arbitrary SCEP messages and runs them as a differential across implementations, and it is available at [github.com/cbev0x/SCEPMutator](https://github.com/cbev0x/SCEPMutator). The characterization is, as far as I can tell, the first published five-way SCEP differential. If you run SCEP in production, the practical takeaways are concrete: your strict-DER clients will choke on NDES and OpenXPKI CA bundles, micromdm downgrades its reply cipher to single DES, Dogtag crashes closed and leaks stack traces where the others fail cleanly, and the native NDES parser is the most robust of the five rather than the least. And if you want to look for the bug I did not find, you now have the harness to start from.
