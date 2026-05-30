# Asset Enumeration

End-to-end discovery of a company's external attack surface: subsidiaries → domains/IPs → subdomains → cloud infrastructure. This is the first and broadest phase of passive recon.

## 1. Subsidiaries

You know the company you are attacking and probably its main domain - but what about its subsidiaries? They are also in scope and could be easier targets.

| Source | URL | Notes |
|---|---|---|
| **Google** | `google.com` | Search `"<company>" subsidiary` / `"acquired by <company>"` / annual reports |
| **Crunchbase** | https://www.crunchbase.com/ | Company insights, funding, acquisitions, leadership |
| **Aleph (OCCRP)** | https://aleph.occrp.org/ | Investigative-journalism dataset; corporate registries, leaks |
| **ChatGPT** | https://chat.openai.com/auth/login | Data only up to its training cutoff; useful for historical org structures |

Always corroborate AI-derived subsidiary lists against Crunchbase or the company's own filings - the model will fabricate plausible-sounding entities.

## 2. Getting Domains and IPs

### 2.1 Reverse WHOIS

Since you know the parent + subsidiaries, use reverse-WHOIS to pivot from organization name / registrant email back to every domain registered under it.

| Tool | URL | Notes |
|---|---|---|
| **ViewDNS** | https://viewdns.info/ | Free reverse-whois, DNS history |
| **Whoxy** | https://www.whoxy.com/ | Historical WHOIS + reverse whois by company / owner / email. Paid API: $2 per 1,000 lookups |
| **NetworksDB** | https://networksdb.io/ | Mass reverse DNS, reverse Whois, lists of registered domains, IP owners |

Pivot loop: company name → domains → registrant emails → more domains → new company aliases → repeat.

### 2.2 GDPR-restricted European TLDs

European WHOIS is heavily redacted under GDPR. Use the country NIC directly. Example for Spain:

| TLD | NIC |
|---|---|
| `.es` | https://www.dominios.es/es |

When stuck on an EU TLD, search the registry's own database rather than generic WHOIS portals.

### 2.3 IP ranges & ASNs - Regional Internet Registries

Try to search for IP ranges, ASNs etc. linked to a given organization. Don't forget to also pull all possible domains associated with those IPs. Also, get domains associated with IPs you know are pointed at by the org's domains - you may find something new.

After NetworksDB aggregates data, validate against the canonical RIR for each region:

| Registry | URL | Region |
|---|---|---|
| **IANA WHOIS** | https://www.iana.org/whois | Top-level, points to correct RIR |
| **ARIN (RDAP)** | https://search.arin.net/rdap/ | North America |
| **RIPE Webupdates** | https://apps.db.ripe.net/db-web-ui/fulltextsearch | Europe / Middle East |
| **APNIC** | https://www.apnic.net/about-apnic/whois_search/ | Asia Pacific |
| **LACNIC** | https://query.milacnic.lacnic.net/home | Latin America / Caribbean |
| **AFRINIC** | https://whois-web.afrinic.net/ | Africa |

### 2.4 TLS certificates (domains AND subdomains)

TLS certificates are a great source for both apex domains AND subdomains - the SAN field often lists internal hostnames that aren't in DNS.

| Tool | URL | Notes |
|---|---|---|
| **crt.sh** | https://crt.sh/ | Free Certificate Transparency log search (Sectigo / formerly Comodo CA) |
| **crtRecon.go** | https://github.com/sikumy/ethical-hacking/blob/main/recon/crtRecon.go | CLI for crt.sh, easier to script |
| **Shodan** | shodan.io | Use filter `org:<org>` or `hostname:<domain>` and download JSON |
| **Censys** | censys.io | Same idea - bulk export |
| **SecurityTrails / haktrails** | https://github.com/hakluke/haktrails | Golang client for SecurityTrails API (watch the quota) |

Parse Shodan JSON for cert SANs:

```bash
shodan parse --fields ip_str,org,hostnames,ssl.cert.subject.CN,ssl.cert.subject.SAN --separator "," Shodan.json
```

### 2.5 Reverse DNS

Walk known IP ranges and turn the addresses into hostnames:

```bash
prips <IP_RANGE> | hakrevdns
```

### 2.6 Related-tech pivots

| Tool | URL | What it gives you |
|---|---|---|
| **BuiltWith** | https://builtwith.com/ | Other domains using the same tech stack, analytics IDs, ad IDs |

Analytics IDs (Google Analytics, AdSense, Facebook Pixel) are gold - they tie sister sites together that share no obvious WHOIS or DNS relationship.

## 3. Subdomains

| Tool | Command | Notes |
|---|---|---|
| **amass** | `amass enum -passive -d example.com -o amass_passive.txt` | Aggregator over many sources |
| **dnsenum** | `dnsenum --noreverse -o file.xml <domain>` | Classic; XML output for tooling |
| **assetfinder** | `assetfinder [--subs-only] <Domain> > hostsAsset.txt` | Fast; pull from public sources |
| **subfinder** | `subfinder -dL <list>.txt > hostSubfinder.txt` | Configure SecurityTrails, Shodan, GitHub and other APIs in its config for max coverage |
| **crt** (cemulus/crt) | https://github.com/cemulus/crt | CLI for Certificate Transparency logs |
| **PureDNS** | https://github.com/d3mondev/puredns | Fast resolver + subdomain bruteforce, filters wildcard / DNS-poisoned entries |

Run several in parallel against the same target, then `sort -u` the results - each tool finds things the others miss.

## 4. Source code platforms

GitHub, GitLab (or whichever your target uses) often contain hard-coded internal domains, subdomains, IPs, and secrets in commit history. Search the org's public repos and contributor profiles.

## 5. Scanning the cloud

All the above focuses on infra owned directly by the target. But many assets sit on AWS / Azure / GCP / etc. Scanning the entire cloud yourself takes forever, so use groups that pre-scan and publish:

| Source | URL |
|---|---|
| **sni-ip-ranges** | https://kaeferjaeger.gay/?dir=sni-ip-ranges |

Download the published scans, then `grep` / parse for your target domains' SNI values to discover cloud IPs hosting their assets.

## Cross-references

- For Google dorks to expand the source-code platform search in step 4 → `search-engine-dorking.md`
