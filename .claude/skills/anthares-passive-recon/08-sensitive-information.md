# 8. Sensitive Information Discovery

## 8.1 OSINT Tools

| Tool | Purpose |
|------|---------|
| TheHarvester | Emails, names, subdomains, IPs, URLs from public sources |
| Sherlock | Username enumeration across social networks |

## 8.2 Breach Data

**Always check for breaches** — compromised credentials can provide direct access.

| Service | URL | Notes |
|---------|-----|-------|
| HaveIBeenPwned | https://haveibeenpwned.com | Check if domain/email is in known breaches |
| Pastebin | https://pastebin.pl | Search for leaked data if breach confirmed |
| Dehashed | https://www.dehashed.com | Plaintext passwords, hashed creds, full breach records |
| BreachDirectory | https://breachdirectory.org | Free; shows first 4 chars + length + SHA1 hash. Passwords ≤10-11 chars → crack with Hashcat |

**BreachDirectory workflow:**
1. Query email/domain
2. Note the SHA1 hash and password length
3. If length ≤ 11 chars: crack with `hashcat -m 100` (SHA1 mode)

## 8.3 Public Secrets in Code

Scan public repos for hardcoded API keys, tokens, credentials:
- **TruffleHog:** https://github.com/trufflesecurity/trufflehog

```bash
# Scan a GitHub org
trufflehog github --org=<target_org>

# Scan a specific repo
trufflehog git https://github.com/<target>/<repo>
```

## 8.4 Public Cloud Storage (S3, Azure Blobs, GCP Buckets)

Enumerate publicly accessible cloud storage buckets:
- **GrayhatWarfare:** https://grayhatwarfare.com — searchable index of public AWS S3, Azure Blob, and GCP buckets

## 8.5 Email Discovery and Enumeration

Multiple tools and services for finding and validating company emails:

| Tool/Service | URL | Notes |
|-------------|-----|-------|
| Phonebook.cz | https://phonebook.cz | Emails, domains, URLs; **reveals passwords indexed in URLs** |
| Prospeo | https://prospeo.io | Business email finder |
| Infoga | https://github.com/m4ll0k/Infoga | Email OSINT — sources, breaches, leaks |

**Email spoofing check:** Test whether the domain's SPF/DKIM/DMARC allows spoofing — a weak or missing policy means email impersonation is trivial.

## 8.6 O365 / Microsoft 365 User Enumeration

Validate whether discovered emails exist in an O365 tenant **without submitting login attempts** (no lockout risk):

| Tool | URL | Notes |
|------|-----|-------|
| onedrive_user_enum | https://github.com/nyxgeek/onedrive_user_enum | Enumerate valid O365 users via OneDrive |
| Go365 | https://github.com/optiv/Go365 | O365 user attack tool; also supports password spraying |
| o365creeper | https://github.com/LMGsec/o365creeper | Validates emails against O365 without login attempts |
| o365spray | https://github.com/0xZDH/o365spray | Username enumeration + password spraying for O365 |

> **OPSEC:** User enumeration without auth is low-noise. Password spraying is NOT passive — confirm authorization before using spray capabilities.

## 8.7 OSINT Framework

General OSINT reference organized by category (people, domains, email, social, etc.):
- https://osintframework.com
