# 6. Cloud Asset Discovery

Target infrastructure is often spread across AWS, Azure, and GCP. Pre-scanned datasets exist — use them instead of active scanning.

## 6.1 SNI IP Ranges — Pre-Scanned Cloud Data

Community-maintained scans of major cloud providers, organized by SNI hostname:
- **kaeferjaeger.gay:** https://kaeferjaeger.gay/?dir=sni-ip-ranges

Download relevant cloud provider file, then parse for target domains:
```bash
# Download and grep for target
wget https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_ranges_merged.txt
grep -i "target.com" ipv4_ranges_merged.txt

# Or parse JSON output for structured data
cat <provider>_ranges.json | jq '.[] | select(.sni | contains("target.com"))'
```
