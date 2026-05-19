# Anthares Passive Recon — Quick Reference

## Quick Reference — Tool Cheatsheet

| Phase | Tool | Command / URL |
|-------|------|---------------|
| Subsidiaries | Crunchbase | https://www.crunchbase.com |
| Subsidiaries | Aleph | https://aleph.occrp.org |
| Reverse WHOIS | ViewDNS | https://viewdns.info/reversewhois/ |
| Reverse WHOIS | Whoxy | https://www.whoxy.com |
| Related domains | BuiltWith | https://builtwith.com |
| ASN/IP | NetworksDB | https://networksdb.io |
| Certificates | crt.sh | https://crt.sh |
| SecurityTrails | haktrails | `echo domain \| haktrails subdomains` |
| Reverse DNS | hakrevdns | `prips <range> \| hakrevdns` |
| Subdomains | subfinder | `subfinder -dL domains.txt` |
| Subdomains | assetfinder | `assetfinder --subs-only <domain>` |
| Subdomains | dnsenum | `dnsenum --noreverse -o out.xml <domain>` |
| Subdomains | PureDNS | `puredns bruteforce <wordlist> <domain>` |
| HTTP alive | httpx | `httpx -l subs.txt -status-code -follow-redirects` |
| DNS visual | DNSdumpster | https://dnsdumpster.com |
| CDN bypass | CloudFlair | `python cloudflare.py -d <domain>` |
| CDN bypass | Cloudmare | `python cloudmare.py <domain>` |
| Cloud assets | GrayhatWarfare | https://grayhatwarfare.com |
| Cloud scans | kaeferjaeger | https://kaeferjaeger.gay/?dir=sni-ip-ranges |
| Shodan bulk | Shodan CLI | `while read l; do shodan host $l; done < ips.txt` |
| Breach check | HaveIBeenPwned | https://haveibeenpwned.com |
| Breach data | Dehashed | https://www.dehashed.com |
| Public secrets | TruffleHog | `trufflehog github --org=<org>` |
| Emails | Phonebook.cz | https://phonebook.cz |
| Emails | Prospeo | https://prospeo.io |
| O365 enum | o365creeper | https://github.com/LMGsec/o365creeper |
| O365 enum | o365spray | https://github.com/0xZDH/o365spray |
| OSINT ref | OSINT Framework | https://osintframework.com |
| Dorks | pentest-tools | https://pentest-tools.com/information-gathering/google-hacking |
| Dorks | haax.fr | https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/ |

---

## OPSEC Notes

- All techniques in this skill are **passive** — no direct interaction with target systems
- O365 user enumeration is low-noise; password spraying is active and noisy — requires explicit authorization
- Shodan/Censys queries are passive (querying third-party databases, not the target)
- TruffleHog on public GitHub repos is passive; scanning internal repos requires authorization
- Cloud bucket enumeration via GrayhatWarfare is passive (pre-indexed data)
- Reverse DNS lookups query public DNS resolvers — low noise, no target interaction
