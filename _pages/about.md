---
title: About
permalink: /about/
layout: single
author_profile: true
---

# cbev

Offensive security researcher and tool developer focused on Active Directory, Kerberos, and Windows authentication internals. I build Linux-native offensive tooling, validate it against instrumented AD labs, and publish internals-first research before I publish offensive technique.

Currently pursuing offensive security roles (penetration testing and red team) at boutique security consultancies.

---

## Certifications

| Certification                                    | Status        |
| ------------------------------------------------ | ------------- |
| CompTIA Security+                                | Achieved      |
| eJPT - eLearnSecurity Junior Penetration Tester  | Achieved      |
| OSCP - Offensive Security Certified Professional | Achieved      |
| BSCP - Burp Suite Certified Practitioner         | In progress   |
| CRTO - Certified Red Team Operator               | In progress   |
| CRTE - Certified Red Team Expert                 | Planned       |

---

## Skills & Focus Areas

**Active Directory & Kerberos** Delegation abuse (RBCD, constrained, unconstrained), AS-REP roasting, Kerberoasting, shadow credentials, PKINIT, UnPAC-the-hash, AD CS ESC exploitation (ESC1-ESC16), authentication coercion (MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP), NTLM relay, authentication reflection, BloodHound/SharpHound enumeration.

**Windows Authentication Internals** NTLM relay mechanics and the mitigations that matter (EPA, SMB signing, channel binding), Kerberos delegation internals, PKINIT and certificate mapping, and the NTLM-deprecation replacement surface (IAKerb, Local KDC, IP SPN).

**Web Application Security** SQLi (including blind and second-order), SSTI, SSRF, deserialization (Java/.NET), JWT attacks, XXE, IDOR, LFI/RFI, command injection, and XSS-to-account-takeover chains.

**Tooling & Automation** Linux-native offensive tooling with Python and Impacket. OPSEC-aware tool design: event telemetry is measured against a live SIEM to quantify noise profiles before anything ships.

**Lab & Detection** Custom AD labs running current Windows Server 2025 defaults (plus 2022/2019 for delegation work) with Elastic SIEM, Winlogbeat, and Sysmon. Used for tool validation, empirical event-ID mapping, and Sigma rule authoring.

---

## Research

Internals-first research with tooling built alongside each track. Published series:

- **AD CS Abuse Research** (5 parts) - PKI trust mechanics through the full ESC taxonomy. Ships with CS².
- **Windows Authentication Coercion to NTLM Relay** (4 parts) - every coercion vector tested against Server 2025 defaults. Ships with impel.
- **Windows Authentication Reflection** (2 parts) - the reflection family and a lab reproduction of CVE-2026-24294 with a Sigma detection rule.
- **Kerberos Delegation** - architecture and OPSEC profile of each delegation primitive. Ships with DeleGator.

**Current direction:** Windows Server 2025 novel attack surface, specifically the NTLM-deprecation replacement layer (IAKerb, Local KDC, IP-based SPNs), with a fresh instrumented lab being provisioned for telemetry mapping.

See [Tools & Projects](/tools/) for the full breakdown, and [Archives](/archives/) for the complete writeup index including 100+ HTB and TryHackMe machine writeups.

---

## Tools

| Tool                                             | Description                                                                                                                                                                                       |
| ------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [DeleGator](https://github.com/cbev0x/DeleGator) | Linux-native Kerberos delegation abuse framework. Covers RBCD, constrained (with and without protocol transition), and unconstrained delegation. Enumeration-first design with OPSEC noise profiling. |
| [CS²](https://github.com/cbev0x/CS2)             | Linux-native AD CS enumeration and exploit-chain framework covering ESC1-ESC16. Enumerates templates, ACLs, and OID-to-group mappings, then correlates them into prioritized exploit chains.     |
| [impel](https://github.com/cbev0x/impel)         | Linux-native RPC coercion surface scanner. Harvests RPC interfaces, scores reachable coercion vectors, probes EPM bypasses, and executes the confirmed vector against the target.                |

---

## Platforms

- **HackTheBox** - [app.hackthebox.com/users/2669350](https://app.hackthebox.com/users/2669350)
- **TryHackMe** - [tryhackme.com/p/cbev](https://tryhackme.com/p/cbev)
- **GitHub** - [github.com/cbev0x](https://github.com/cbev0x)

---

## Contact

Reach out via [LinkedIn](https://www.linkedin.com/in/chase-bevan-thomas-59b105363/) or open an issue on any of my GitHub repos.

> All content on this site is for educational purposes only. Never test techniques on systems you do not own or have explicit written permission to test.
