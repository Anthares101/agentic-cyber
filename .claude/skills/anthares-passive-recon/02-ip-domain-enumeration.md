# 2. IP Space and Domain Enumeration

## 2.1 Reverse WHOIS — Find All Domains by Company/Owner/Email

- **ViewDNS Reverse Whois:** https://viewdns.info/reversewhois/
- **Whoxy:** https://www.whoxy.com — reverse whois by company name, owner, or email; includes historical IP/WHOIS data
- **DomainTools:** https://whois.domaintools.com
- **ViewDNS.info:** https://viewdns.info — multiple lookup types

**CLI WHOIS** — reveals the responsible unit for TLDs; search for already-registered related domains:
```bash
whois <domain>
```

**Spanish `.es` domains** (restricted data — use dedicated registry):
- https://www.dominios.es/es

## 2.2 Related Domains via Technology Fingerprinting

- **BuiltWith:** https://builtwith.com — find related domains sharing the same tech stack, analytics IDs, or tracking codes

## 2.3 ASN and IP Range Discovery

Map IP ranges and ASNs linked to the organization. Then enumerate domains pointing to those IPs — you may discover previously unknown assets.

- **NetworksDB:** https://networksdb.io — company → IP, ASN, reverse whois, reverse DNS

**Shodan** — filter by organization or hostname, download JSON:
```bash
# In Shodan web UI
org:"<Organization Name>"
hostname:"<domain>"

# Parse downloaded Shodan JSON
shodan parse --fields ip_str,org,hostnames,ssl.cert.subject.CN,ssl.cert.subject.SAN --separator ", " Shodan.json
```

**Censys** — similar to Shodan, useful for certificate and service data.

## 2.4 TLS Certificate Enumeration

Certificates reveal domains and subdomains (SAN fields):

- **crt.sh:** https://crt.sh — search `%.target.com` for wildcard SAN entries
- **crtRecon Go tool:** https://github.com/sikumy/ethical-hacking/blob/main/recon/crtRecon.go

## 2.5 SecurityTrails via haktrails

Query SecurityTrails API for historical DNS, subdomains, and associated IPs. Watch your API quota.

```bash
# Tool: https://github.com/hakluke/haktrails
echo "target.com" | haktrails subdomains
echo "target.com" | haktrails associateddomains
```

## 2.6 Reverse DNS Lookups

Reverse DNS on known IP ranges may reveal internal naming conventions and hidden assets:

```bash
prips <IP_RANGE> | hakrevdns
# Example: prips 192.168.1.0/24 | hakrevdns
```
