# 3. Subdomain Enumeration

Use multiple tools in parallel — each has different data sources.

## 3.1 dnsenum

DNS enumeration with zone transfer attempts, brute force, and reverse lookups:
```bash
dnsenum --noreverse -o file.xml <domain>
```

## 3.2 assetfinder

Finds subdomains from multiple passive sources:
```bash
assetfinder [--subs-only] <domain> > hostsAsset.txt
```

## 3.3 subfinder

Highly configurable, supports SecurityTrails, Shodan, GitHub, Censys APIs:
```bash
# Single domain
subfinder -d <domain> > hostSubfinder.txt

# Multiple domains from list
subfinder -dL <domains_list>.txt > hostSubfinder.txt
```
Configure API keys in `~/.config/subfinder/provider-config.yaml` for maximum coverage.

## 3.4 crt (Certificate Transparency CLI)

Check certificate transparency logs per domain:
```bash
# Tool: https://github.com/cemulus/crt
crt <domain>
```

## 3.5 PureDNS — Subdomain Bruteforcing

Fast resolver with wildcard filtering and DNS poisoning protection:
```bash
# Tool: https://github.com/d3mondev/puredns
puredns bruteforce <wordlist> <domain>
puredns resolve <subdomains_list> --resolvers <resolvers.txt>
```
