---
name: anthares-passive-recon
description: Use when performing passive reconnaissance and enumeration against a target company perimeter — covers subsidiary discovery, domain/IP space mapping, subdomain enumeration, CDN bypass, cloud asset discovery, service fingerprinting, sensitive data exposure (breaches, secrets, credentials, emails), O365 user enumeration, and Google/search-engine dorking — all without active scanning or direct interaction with target systems.
---

# Anthares Passive Recon

Structured passive reconnaissance methodology for mapping a company's full external attack surface without triggering IDS/WAF/EDR. Covers everything from subsidiary discovery to breach data and cloud assets.

## Methodology Order

```
Subsidiaries → IP/Domain Space → Subdomains → Polishing/Validation
→ CDN Bypass → Cloud Assets → Service Info → Sensitive Data → Dorks
```

This skill is modular — load only the file(s) relevant to the phase you are working on. The main file is a navigation hub; full content lives in the linked category files.

---

## File Map

| Phase | File | Content |
|-------|------|---------|
| 1 | [01-subsidiary-discovery.md](01-subsidiary-discovery.md) | Crunchbase, Aleph, Google, LinkedIn — subsidiary and corporate-tree mapping |
| 2 | [02-ip-domain-enumeration.md](02-ip-domain-enumeration.md) | Reverse WHOIS, BuiltWith, ASN/IP, Shodan, Censys, TLS certs, SecurityTrails, reverse DNS |
| 3 | [03-subdomain-enumeration.md](03-subdomain-enumeration.md) | dnsenum, assetfinder, subfinder, crt, PureDNS |
| 4 | [04-polishing-validation.md](04-polishing-validation.md) | GitHub recon, social media, IP extraction, liveness, public/private split, httpx, DNSdumpster |
| 5 | [05-cdn-bypass.md](05-cdn-bypass.md) | Cloudflare/Sucuri/Incapsula bypass — CloudFlair, Cloudmare, historical DNS/TLS |
| 6 | [06-cloud-assets.md](06-cloud-assets.md) | Cloud asset discovery via kaeferjaeger SNI IP ranges |
| 7 | [07-service-info.md](07-service-info.md) | Passive port/service info — Shodan bulk host lookup, filters |
| 8 | [08-sensitive-information.md](08-sensitive-information.md) | OSINT tools, breaches, public secrets, cloud storage, emails, O365 user enum |
| 9 | [09-google-dorks.md](09-google-dorks.md) | Dork references, high-value queries, multi-engine strategy |
| 10 | [10-compass-osint.md](10-compass-osint.md) | Full Compass Security OSINT Cheat Sheet — Google/Bing/Yandex, archives, Shodan filters, social network OSINT, key tools, books |
| Ref | [reference.md](reference.md) | Quick tool cheatsheet + OPSEC notes |

---

## Decision Tree — Where to Start

```
Are you scoping a brand-new target company?
  → Start with 01-subsidiary-discovery.md, then 02-ip-domain-enumeration.md

Do you already have a domain and want subdomains?
  → Jump to 03-subdomain-enumeration.md → 04-polishing-validation.md

Target is behind Cloudflare/Sucuri/Incapsula?
  → 05-cdn-bypass.md

Looking for cloud-hosted assets (AWS/Azure/GCP)?
  → 06-cloud-assets.md

Need open-port/service info without scanning?
  → 07-service-info.md (Shodan)

Hunting credentials, breaches, secrets, emails, O365 users?
  → 08-sensitive-information.md

Need to find indexed sensitive documents/admin panels?
  → 09-google-dorks.md

Person/social-media OSINT or advanced search-engine operators?
  → 10-compass-osint.md

Need a quick command lookup?
  → reference.md
```

---

## OPSEC Summary

- All techniques in this skill are **passive** — no direct interaction with target systems.
- Some sub-techniques (e.g., O365 password spraying in section 8) are **NOT passive** — confirm authorization before using.
- See [reference.md](reference.md) for the full OPSEC notes and tool cheatsheet.

---

## Source Material

Based on the Anthares Passive Recon methodology and the Compass Security OSINT Cheat Sheet (2017-01). All original content is preserved across the modular files.
