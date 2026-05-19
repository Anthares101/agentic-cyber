# 4. Polishing and Validation

After collecting raw domain/subdomain lists, validate and organize results.

## 4.1 Source Code Repositories

Check GitHub, GitLab, Bitbucket, or whatever platform the target uses — developers often hardcode subdomains, internal endpoints, and IP addresses in code:
- Search: `org:<target_github_org>` in GitHub
- Look for configuration files, CI/CD pipelines, `.env` examples

## 4.2 Social Media

LinkedIn, Twitter/X, job postings — technology stack clues, internal tool names, new acquisitions not yet on Crunchbase.

## 4.3 Extract IPv4 Addresses from Files

Useful when parsing APK files, JS bundles, leaked code, or any text:
```bash
grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' <file> | sort -u
```

## 4.4 Resolve Domains and Check Liveness

Verify domains actually resolve — dead domains are noise:
```bash
while read line; do
  echo "$line --> $(dig +short $line)"
done < domains.txt > results.txt
```

## 4.5 Categorize Public vs Private Assets

Use `domains_to_assets.py` to resolve domains AND organize them into public (routable) vs private (RFC1918/internal) assets:
- Script: https://github.com/anthares101/utility-scripts/blob/master/ethical-hacking/domains_to_assets.py

Internal domains are noted for later — they may become reachable via VPN, SSRF, or pivoting.

## 4.6 HTTP Asset Discovery with httpx

Filter only live HTTP/HTTPS services — pipe only active assets to downstream tools:
```bash
httpx -l subDomains.txt -o Activesubs.txt -threads 200 -status-code -follow-redirects
```
> Note: Binary may be aliased as `httpxdiscovery` in some setups.

## 4.7 Additional DNS Recon Tools

- **DNSdumpster:** https://dnsdumpster.com — passive DNS recon, visualizes DNS records and related hosts
