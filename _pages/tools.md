---
title: Tools & Projects
permalink: /tools/
layout: single
author_profile: true
---

Original tooling and research artifacts. Everything is Linux-native, built against instrumented Active Directory labs, and validated before release. OPSEC characteristics are measured against live telemetry (Elastic SIEM, Winlogbeat, Sysmon), not estimated.

---

### DeleGator

**Linux-native Kerberos delegation abuse framework**

[![GitHub](https://img.shields.io/badge/GitHub-cbev0x%2FDeleGator-black?style=flat-square&logo=github)](https://github.com/cbev0x/DeleGator)

Covers the three delegation primitives in a single enumeration-first workflow:

| Mode              | Technique                             | Notes                                                      |
| ----------------- | ------------------------------------- | ---------------------------------------------------------- |
| `--rbcd`          | Resource-Based Constrained Delegation | Writes `msDS-AllowedToActOnBehalfOfOtherIdentity` via LDAP |
| `--constrained`   | Constrained Delegation                | S4U2Proxy; protocol transition supported via `--s4u2self`  |
| `--unconstrained` | Unconstrained Delegation              | Coercion-ready; prints TGT on capture                      |
| `--enum`          | Delegation enumeration                | Queries all three types across the domain before acting    |

**OPSEC findings from lab telemetry (Elastic SIEM + Sysmon):**

- ccache-based auth produces roughly 18x fewer authentication events than password-based auth by eliminating NTLM 4625/4776 sequences
- S4U2Self is permanently fingerprinted by `TicketOptions` value `0x40810000` in Event 4769, detectable by tuned SIEM rules
- RBCD writes generate Event 4742 (computer account modified) and are detectable without SACL auditing
- Unconstrained delegation coercion triggers Event 4768 from the coerced host

**Stack:** Python 3, Impacket 0.13.x. Tested against Windows Server 2022/2019 and validated on HTB (Freelancer, Intelligence, Rebound).

[Build and OPSEC writeup →](https://cbev0x.github.io/personal/research/tooling/2026/06/02/DeleGator.html)

---

### CS² (Certificate Services Chain Saw)

**Linux-native AD CS enumeration and exploit-chain framework, ESC1-ESC16**

[![GitHub](https://img.shields.io/badge/GitHub-cbev0x%2FCS2-black?style=flat-square&logo=github)](https://github.com/cbev0x/CS2)

Full-taxonomy AD CS enumeration that correlates findings into prioritized, ready-to-run exploit chains. Four modules:

| Module       | Role                                                                                     |
| ------------ | ---------------------------------------------------------------------------------------- |
| `find.py`    | Certificate template and CA enumeration; ESC1-ESC16 misconfiguration detection           |
| `acls.py`    | DACL enumeration over PKI objects, templates, and CA host                                 |
| `mapping.py` | OID-to-group link resolution (`msDS-OIDToGroupLink`) for ESC13 issuance-policy analysis   |
| `chain.py`   | Graph correlation of all findings into prioritized exploit chains with OPSEC event notes  |

**Notable details:**

- Remote registry-based confirmation of ESC9/ESC10 exploitability rather than inference from template flags alone
- Original finding: `msDS-OIDToGroupLink` requires Universal-scope groups to link, an underdocumented constraint that changes ESC13 exploitability
- Each chain output includes the event IDs a defender would see, so detection posture is visible up front

**Stack:** Python 3, Impacket. Companion to the five-part AD CS Abuse Research series below.

---

### impel

**Linux-native RPC coercion surface scanner for Windows AD**

[![GitHub](https://img.shields.io/badge/GitHub-cbev0x%2Fimpel-black?style=flat-square&logo=github)](https://github.com/cbev0x/impel)

Enumerates, scores, and validates authentication coercion vectors against a target before firing them. Built as the tooling capstone of the coercion-to-relay research series.

| Capability          | Detail                                                                             |
| ------------------- | ---------------------------------------------------------------------------------- |
| UUID harvesting     | Enumerates registered RPC interfaces to find coercion-capable endpoints            |
| Surface scoring     | Three-axis scoring to rank which vectors are actually reachable and worth trying   |
| EPM-bypass probing  | Tests direct named-pipe binds where the Endpoint Mapper is filtered                |
| Coercion execution  | Fires the confirmed vector: MS-RPRN, MS-EFSR, MS-DFSNM, MS-FSRVP                    |

Empirically mapped against current Windows Server 2025 defaults. Key measured result from the research: MS-DFSNM was the sole working coercion vector on a January 2026 patch-level Server 2025 host, with MS-RPRN mitigated at two layers.

**Stack:** Python 3, Impacket.

[Tool and coercion-mapping writeup →](https://cbev0x.github.io/personal/research/tooling/2026/07/09/impel_tool_and_coercion_mapping.html)

---

## Writeup Series

### AD CS Abuse Research (5 parts)

Internals-first coverage of the AD CS attack surface, from PKI trust mechanics through the full ESC taxonomy. Written alongside CS² development.

- [Part 1: PKI Internals and Certificate Enrollment](https://cbev0x.github.io/personal/2026/06/04/AD_CS_Abuse_Research_part_1.html)
- [Part 2: Weak Mapping and the ESC9/ESC10 Attack Class](https://cbev0x.github.io/personal/2026/06/06/AD_CS_Abuse_Research_part_2.html)
- [Part 3: AD Object Write Primitives](https://cbev0x.github.io/personal/2026/06/08/AD_CS_Abuse_Research_part_3.html)
- [Part 4: Relay-Based Attacks (ESC8, ESC11)](https://cbev0x.github.io/personal/2026/06/09/AD_CS_Abuse_Research_part_4.html)
- [Part 5: OID and Issuance Policy Abuse, and the Complete ESC Reference](https://cbev0x.github.io/personal/2026/06/10/AD_CS_Abuse_Research_part_5.html)

### Windows Authentication Coercion to NTLM Relay (4 parts)

Systematic test of every coercion vector against current Windows Server 2025 defaults in an isolated lab, mapping which still work and which are mitigated. Companion research to impel.

- [Part 1: Fundamentals](https://cbev0x.github.io/personal/2026/06/23/Coercion_to_Relay_Research_part_1.html)
- [Part 2: Relay Target Mechanics](https://cbev0x.github.io/personal/2026/06/23/Coercion_to_Relay_Research_part_2.html)
- [Part 3: The Matrix](https://cbev0x.github.io/personal/2026/06/26/Coercion_to_Relay_Research_part_3.html)
- [Part 4: LDAP/LDAPS Relay and ESC8 Against Server 2025 Defaults](https://cbev0x.github.io/personal/2026/06/27/Coercion_to_Relay_Research_part_4.html)

### Windows Authentication Reflection (2 parts)

The authentication reflection family and its lineage, then a full lab reproduction of CVE-2026-24294 against Server 2025 defaults with ELK telemetry and a Sigma detection rule.

- [Part 1: The Mechanic and Its Lineage](https://cbev0x.github.io/personal/2026/07/07/Authentication_Reflection_Research_part_1.html)
- [Part 2: CVE-2026-24294 in the Lab](https://cbev0x.github.io/personal/2026/07/08/Authentication_Reflection_Research_part_2.html)

### Kerberos Delegation

Build, architecture, and OPSEC profile of each delegation primitive, written alongside DeleGator.

- [DeleGator: Building and Testing a Linux-Native Kerberos Delegation Abuse Framework](https://cbev0x.github.io/personal/research/tooling/2026/06/02/DeleGator.html)

---

## Current Research

Windows Server 2025 novel attack surface, focused on the NTLM-deprecation replacement layer: IAKerb, Local KDC, and IP-based SPNs. Fresh instrumented lab with ELK ingest is being provisioned for empirical telemetry mapping.

---

> All tools and research are published for educational and authorised testing purposes only.
> Never use these techniques against systems you do not own or have explicit written permission to test.
