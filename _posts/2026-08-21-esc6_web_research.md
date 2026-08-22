---
title: "The Web-Facing ESC6: SAN Injection Over CEP/CES"
date: 2026-08-21
categories: [Personal, Research]
tags: [Windows, Active Directory, AD CS, CEP, CES, HTTPS, Enrollment, Research]
published: true
---

The Certificate Enrollment Web Service (CES) forwards a `SAN` AdditionalContext ContextItem to the CA as a SAN request attribute. Where `EDITF_ATTRIBUTESUBJECTALTNAME2` is set, that makes ESC6 exploitable over HTTPS alone, with only a low-privilege credential and no RPC or SMB. The impact is weak-mapping only, because the CA still stamps the authenticated caller's own SID into the security extension, so strong-mapping DCs authenticate the certificate as the requester rather than the SAN target. I wrote the first offensive client that speaks the CES/CEP WSTEP protocol to demonstrate it, since Certipy and the rest of the tooling operate over RPC and never touch this surface.

This is surface expansion plus tooling, not a new vulnerability. ESC6 is a known misconfiguration. What I am adding is the vector and a tool that can reach it.

## Why I looked at CES

Most of the AD CS enrollment surface is well travelled. NDES and SCEP have been worked over, and the WCCE attribute layer has fresh research on it. The one enrollment path with no offensive tooling that actually speaks its protocol is CES and its policy sibling CEP, which use the SOAP-based MS-WSTEP protocol over HTTPS. No public tool implements a WSTEP request, so nobody had characterized what CES does with the request on its way to the CA.

The question I started with is simple. CES authenticates the SOAP client, then submits a request to the CA on that client's behalf. Does it faithfully bind the authenticated caller to what the CA issues, or can a low-privilege caller steer issuance toward someone else? That is a confused-deputy question, and CES sits in exactly the deputy position.

## Background, kept short

CEP and CES are two services. CEP is the policy and authorization service. It answers "which templates may this caller enroll" and hands the client a list. CES is the enrollment service. It receives the request, authenticates the caller, and submits to the CA. They are separate endpoints and can run under different identities.

ESC6 is the CA-side misconfiguration where `EDITF_ATTRIBUTESUBJECTALTNAME2` is set. With that flag, the CA honors a caller-supplied SAN request attribute regardless of what the template says, which is the classic SAN injection that lets a requester put someone else's identity into the certificate.

The 2022 hardening matters for everything below. The CA adds the `szOID_NTDS_CA_SECURITY_EXT` security extension containing the requester's SID, derived from the authenticated token. Strong-mapping domain controllers authenticate on that SID, not on the SAN. That is the ceiling for this entire post, so I am putting it up front.

## Standing up the lab

I built this in an isolated lab on Windows Server 2025: a single-tier Enterprise Root CA on a member server, with CEP and CES co-located, and separate Kerberos and UserName-mode instances so I could compare auth modes.

A few build gotchas cost me a cycle each and will cost you one too:

- Installing an Enterprise CA needs Enterprise Admin rights. If you run it as a plain Domain Admin you get a misleading range-constraint error, not a permissions error.
- The CES application pool identity must be a member of the local `IIS_IUSRS` group before the CES install will run.
- Each CEP instance ships with an `ID` GUID in its web.config that collides with the default AD enrollment policy. Mint a fresh GUID per instance or the client refuses to add it.
- A missing `HTTP/<host>` SPN breaks Kerberos to CES with a blank-user 401.1. One SPN covers every CES app on the host.

## The Windows client will not cooperate

The first thing I found is not the finding, but it shaped everything after. When a domain-joined client enrolls through the UserName-mode policy, it retrieves policy from the UserName CEP and then sends every issuance request to the Kerberos CES. It silently prefers Kerberos.

That means the built-in client cannot reliably drive UserName-mode CES, and certreq fights you the whole way. It also means the client's freedom to pick which CES and which auth method to use is its own small downgrade seam worth noting. The practical consequence: to test UserName mode at all, I needed a raw client that POSTs where I tell it to.

## Building a WSTEP client from faults

I chose to write a raw SOAP client, because it gives full control over every field and because it is the missing tool. I did not have a captured known-good request to copy, so I built the envelope the honest way: start minimal, read each fault, and add exactly the layer it names. WCF and the CES enrollment code are strict and verbose, which makes them a good teacher. This fault ladder is the transferable part of the whole exercise.

The ladder, in order:

1. Empty body with only WS-Addressing headers returns `s:Sender / InvalidSecurity`. The framing is fine, it wants a WS-Security header.
2. Adding a `Timestamp` and a `UsernameToken` flips the fault to `s:Receiver / InternalServiceFault`, and the response now carries a server-signed Security timestamp. That server timestamp is the tell that authentication succeeded. The service threw only because the body was empty.
3. Adding the RST body with a `BinarySecurityToken` carrying the PKCS#10 returns "The Token Type is invalid."
4. The correct `TokenType` is the X.509 token-profile value `...oasis-200401-wss-x509-token-profile-1.0#X509v3`, not the WS-Trust Issue type and not the Microsoft PKCS7 enrollment type. Both of those are rejected.
5. Next fault: "The EncodingType is invalid." The accepted value is the wssecurity-secext form ending in `#base64binary`, lowercase, not the soap-message-security one.
6. Next: "The attributes are invalid," which is the AdditionalContext block being parsed and rejected on shape.
7. With AdditionalContext removed, the CA policy module answers directly: "The request does not contain a certificate template extension or the CertificateTemplate request attribute." That fault is progress, because it means the request reached the CA and got a RequestID. Supplying the template, either as the `szOID` extension in the CSR or as a `CertificateTemplate` ContextItem, produces a clean issue.

That is a working enrollment over UserName-mode CES, driven entirely by my own client, doing the thing the Windows client refused to do. The accepted envelope is in the appendix.

## Baseline: does CES bind identity?

With issuance working, I measured the requester the CA records. Over both Kerberos and UserName CES, the CA records the requester as the authenticated caller. Identity flows through.

Then I tried to break that binding. I injected a `RequesterName` ContextItem naming a different principal through AdditionalContext, authenticated as the low-privilege user. The CA ignored it. The issued certificate's subject stayed the caller, and more importantly the `szOID_NTDS_CA_SECURITY_EXT` still held the caller's SID (`S-1-5-21-<domain>-1105`). The identity binding holds, and it holds at the extension the DC actually authenticates on. That is a clean negative, and it set up the interesting part by proving the AdditionalContext channel does not let me override identity.

## The one thing that did forward: SAN

The AdditionalContext channel is not inert, though. The `CertificateTemplate` ContextItem selects the template, which proves CES forwards ContextItems to the CA and acts on at least some of them. So the real question became: which others forward, and does any of them influence issuance in a way the caller should not control?

I swept a set of candidate ContextItems. The one that lands is a ContextItem literally named `SAN` with a `type=value` payload:

```
SAN -> upn=administrator@domain.local
```

The results, gated cleanly on the EDITF flag:

| EDITF_ATTRIBUTESUBJECTALTNAME2 | injected SAN result |
|---|---|
| OFF (default) | ignored across every vector, certificate carries the caller's own UPN |
| ON | issued certificate SAN = `administrator@domain.local` |

The negatives sharpen it. A ContextItem named `SubjectAltName` is not recognized. A ContextItem named `upn` is not recognized. A value with the certreq-style `SAN:` prefix faults, because that prefix is command-line syntax and not a ContextItem value. A SAN embedded directly in the CSR is stripped for the User template. The accepted carrier is specifically a ContextItem named `SAN`, and CES forwards it to the CA as a SAN request attribute. That is ESC6, reached over CES.

## How far it goes, and the honest ceiling

The obvious next question is whether I can also control the SID extension, because that is what would make this a full win against a modern DC. Post-2022, the way to do that with classic ESC6 is the objectSid URL-SAN trick: smuggle `url=tag:microsoft.com,2022-09-14:sid:S-1-5-21-<domain>-500` so the CA writes the target's SID into the security extension.

I forwarded that through CES the same way. The URL lands in the certificate as a cosmetic SAN entry, but the `szOID_NTDS_CA_SECURITY_EXT` still holds the caller's SID (`...-1105`), not the target's. The CA stamps that extension from the authenticated token and does not take it from the request through this path.

So the impact is weak-mapping or compatibility-mapping impersonation only. Against a strong-mapping Windows Server 2025 DC, a certificate with `administrator@domain.local` in the SAN but the caller's SID in the security extension authenticates as the caller, not as administrator. This is the same ceiling as classic post-2022 ESC6. I want to be clear about that rather than imply a full-domain-admin result that is not there.

## What is actually new

Two things. First, ESC6's SAN-injection primitive is reachable over HTTPS through CES, with no RPC or DCOM. CES is the enrollment surface built for hosts that cannot reach the CA over RPC, which means it is often the surface exposed across network boundaries, in a DMZ, or where SMB and RPC are filtered but 443 is open. So this extends ESC6's reach to wherever CES is exposed, with only a low-privilege credential.

Second, no public offensive tool speaks CEP or CES. I wrote one. It is called `cesreq`, and it issues certificates against a CES endpoint and implements the SAN injection above. Link to the repo - [cesreq](https://github.com/cbev0x/cesreq).

## Detection and defense

There is a detection gap worth its own paragraph. CA issuance auditing (events 4886, 4887, 4888) silently does nothing unless both the CA `AuditFilter` value and the Object Access to Certification Services auditpol subcategory are enabled. I hit this in my own lab: the filter was set but the subcategory had reverted, and no events were written. Many real deployments have the same gap, which means SAN injection over CES can be low-visibility by default.

For detection, watch CES IIS logs for POSTs to `service.svc/CES` from unexpected sources, turn on both halves of CA auditing and alert on 4888 denials, and flag issued certificates where the SAN UPN does not match the requester.

For defense, the root fix is to remove `EDITF_ATTRIBUTESUBJECTALTNAME2`. Beyond that, restrict CES exposure so it is not reachable from untrusted networks, and enforce strong certificate mapping on domain controllers so a SAN-only certificate is inert.

## What did not pan out

The negatives are part of the result, and they are useful to defenders:

- Injecting a `RequesterName` through AdditionalContext is ignored. Identity binding holds.
- Injecting the objectSid URL-SAN does not move the security extension SID. No SID override through this path.
- Requesting a template the low-privilege user lacks Enroll on, straight to CES and bypassing CEP entirely, is denied by the CA on the caller's ACL. Same result whether the template is named via ContextItem or via the CSR extension. CES does not get you past the CA's template ACL.
- A template only the CES service account can enroll, requested as the low-privilege user, is denied. CES impersonates the caller, so there is no service-account fronting.

Taken together, those say the CA's authorization gate holds against the direct CES path. The only thing that crossed was the SAN request attribute, and only under the EDITF misconfiguration.

## cesreq

`cesreq` is a single-file Python client. It speaks UserName-mode CES today, and the auth layer is structured so Kerberos and Certificate modes can drop in. It outputs a PFX with the key and issued certificate, ready for PKINIT, and its `esc6` verb prints the issued SAN and the SID extension so the weak-mapping ceiling is visible in the output rather than hidden.

```
# standard enrollment
cesreq enroll -u 'DOMAIN\user' -p 'password' \
  --target ca01.domain.local --ca 'domain-CA' --no-verify -o user.pfx

# ESC6 SAN injection (needs EDITF_ATTRIBUTESUBJECTALTNAME2)
cesreq esc6 -u 'DOMAIN\user' -p 'password' \
  --ces-url https://ca01.domain.local/domain-CA_CES_UsernamePassword/service.svc/CES \
  --san upn=administrator@domain.local --no-verify -o admin.pfx
```

![](/assets/img/2026-08-21-esc6_web_research/cesreq_demo.png)

## Appendix: the accepted RST envelope

The WS-Security header carries the Timestamp and UsernameToken. The body carries the RST with the correct TokenType, the base64 DER PKCS#10 as a BinarySecurityToken, and the AdditionalContext block. Values that matter and that I got wrong at least once: the `TokenType` is the X509v3 token-profile URI, the `EncodingType` is the secext `#base64binary` URI, and any `&` inside a SAN value must be XML-escaped to `&amp;` or the request is rejected as invalid.

```xml
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
  <s:Header>
    <a:Action s:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep</a:Action>
    <a:MessageID>urn:uuid:...</a:MessageID>
    <a:To s:mustUnderstand="1">https://ca01.domain.local/domain-CA_CES_UsernamePassword/service.svc/CES</a:To>
    <o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <u:Timestamp u:Id="_0"><u:Created>...</u:Created><u:Expires>...</u:Expires></u:Timestamp>
      <o:UsernameToken u:Id="_1">
        <o:Username>DOMAIN\user</o:Username>
        <o:Password Type="...#PasswordText">password</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
      <wst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</wst:TokenType>
      <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>
      <wsse:BinarySecurityToken xmlns:wsse="...secext-1.0.xsd"
        ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
        EncodingType="...secext-1.0.xsd#base64binary">BASE64_DER_PKCS10</wsse:BinarySecurityToken>
      <ac:AdditionalContext xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
        <ac:ContextItem Name="CertificateTemplate"><ac:Value>User</ac:Value></ac:ContextItem>
        <ac:ContextItem Name="SAN"><ac:Value>upn=administrator@domain.local</ac:Value></ac:ContextItem>
      </ac:AdditionalContext>
    </wst:RequestSecurityToken>
  </s:Body>
</s:Envelope>
```

*Lab and authorized testing only. Nothing here is an undisclosed vulnerability; ESC6 is a documented misconfiguration and the EDITF flag is admin-controlled.*
