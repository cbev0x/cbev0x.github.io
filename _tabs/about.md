---
title: About
icon: fas fa-user
order: 4
---

# cbev

Offensive security practitioner focused on Active Directory, Kerberos abuse, and web application exploitation. I build tools, break things in lab environments, and write up what I find.

Currently targeting entry-level roles at boutique security consultancies.

---

## Certifications

| Certification | Status |
|---|---|
| CompTIA Security+ | ✓ Achieved |
| eJPT — eLearnSecurity Junior Penetration Tester | ✓ Achieved |
| OSCP — Offensive Security Certified Professional | ✓ Achieved |
| BSCP — Burp Suite Certified Practitioner | → In progress |
| CRTO — Certified Red Team Operator | → In progress |

---

## Skills & Focus Areas

**Active Directory & Kerberos**
Delegation abuse (RBCD, constrained, unconstrained), AS-REP Roasting, Kerberoasting, shadow credentials, cross-session relay, ADCS ESC chain exploitation (ESC1–ESC14), BloodHound/SharpHound enumeration.

**Web Application Security**
SSTI, SSRF, SQLi, deserialization (Java/.NET), JWT attacks, XXE, IDOR, LFI, command injection. Working through HTB Academy CWES path and curated HTB machines by vulnerability category.

**Tooling & Automation**
Linux-native offensive tooling with Impacket. OPSEC-aware tool design — measuring event telemetry against Elastic SIEM + Sysmon to quantify noise profiles before publishing.

**Lab Infrastructure**
Custom AD lab running Windows Server 2022/2019 with Elastic SIEM, Winlogbeat, and Sysmon. Used for both tool validation and OPSEC research.

---

## Research

Active research track on AD CS (Active Directory Certificate Services) PKI internals and ESC exploitation chains. Two parallel workstreams:

- **Writeup series** — deep technical coverage of PKI trust mechanics and per-ESC exploitation, starting from ESC1 through ESC14. ESC9 and ESC10 complete.
- **Centralized exploitation tool** — targeting ESC techniques with limited existing tooling coverage, Linux-native, Impacket-compatible.

---

## Tools

| Tool | Description |
|---|---|
| [DeleGator](https://github.com/cbev0x/DeleGator) | Linux-native Kerberos delegation abuse framework. Covers RBCD, constrained (with/without protocol transition), and unconstrained delegation. Enumeration-first design with OPSEC noise profiling. |

---

## Platforms

- **HackTheBox** — [app.hackthebox.com/users/2669350](https://app.hackthebox.com/users/2669350)
- **TryHackMe** — [tryhackme.com/p/cbev](https://tryhackme.com/p/cbev)
- **GitHub** — [github.com/cbev0x](https://github.com/cbev0x)

---

## Contact

Reach out via [LinkedIn](https://www.linkedin.com/in/chase-bevan-thomas-59b105363/) or open an issue on any of my GitHub repos.

> All content on this site is for educational purposes only. Never test techniques on systems you do not own or have explicit written permission to test.
