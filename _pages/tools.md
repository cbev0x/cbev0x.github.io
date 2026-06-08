---
title: Tools & Projects
permalink: /tools/
layout: single
author_profile: true
---

Original tooling and research artifacts. Everything is Linux-native and built for real lab validation before release — OPSEC characteristics are measured, not estimated.

---

### DeleGator

**Linux-native Kerberos delegation abuse framework**

[![GitHub](https://img.shields.io/badge/GitHub-cbev0x%2FDeleGator-black?style=flat-square&logo=github)](https://github.com/cbev0x/DeleGator)

Covers the three delegation primitives in a single enumeration-first workflow:

| Mode | Technique | Notes |
|---|---|---|
| `--rbcd` | Resource-Based Constrained Delegation | Writes `msDS-AllowedToActOnBehalfOfOtherIdentity` via LDAP |
| `--constrained` | Constrained Delegation | S4U2Proxy; protocol transition supported via `--s4u2self` |
| `--unconstrained` | Unconstrained Delegation | Coercion-ready; prints TGT on capture |
| `--enum` | Delegation enumeration | Queries all three types across the domain before acting |

**OPSEC findings from lab telemetry (Elastic SIEM + Sysmon):**

- ccache-based auth reduces authentication events vs. password-based by eliminating NTLM Event 4625/4776 sequences
- S4U2Self requests fingerprint via Event 4769 with atypical `TicketOptions` flags — detectable by tuned SIEM rules
- RBCD writes generate Event 4742 (computer account modified) — high-fidelity detection signal
- Unconstrained delegation coercion triggers Event 4768 from the coerced host

**Stack:** Python 3, Impacket 0.13.x, tested against Windows Server 2022/2019

---

### AD CS Exploitation Tool *(in development)*

**Centralized ESC chain exploitation — Linux-native**

A single-tool approach to ADCS ESC exploitation prioritising techniques with limited existing tooling coverage. ESC9, ESC10, ESC13, ESC14 in scope for initial release.

Status: active development. Writeup series running in parallel.

---

## Writeup Series

### AD CS / PKI Deep Dive

| ESC | Technique | Status |
|---|---|---|
| ESC9 | No-security-extension — CT_FLAG_NO_SECURITY_EXTENSION abuse | ✓ Published |
| ESC10 | Weak certificate mappings — UPN/DNS spoofing via `altSecurityIdentities` | ✓ Published |
| ESC14 | Explicit certificate mapping manipulation | → In progress |
| ESC11 | ICPR request relay | → Queued |
| ESC13 | OID group link abuse | → Queued |

### Kerberos Delegation Series

Three-part series covering the architecture and OPSEC profile of each delegation type, written alongside the DeleGator development process. [Read →](/posts/DeleGator/)

---

> All tools and research are published for educational and authorised testing purposes only.
> Never use these techniques against systems you do not own or have explicit written permission to test.
