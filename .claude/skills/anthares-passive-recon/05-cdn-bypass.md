# 5. Finding Real IP Addresses (CDN Bypass)

Services behind Cloudflare, Sucuri, or Incapsula hide the origin server IP. Bypass techniques:

| Technique | Tool/Source |
|-----------|-------------|
| Internet-wide scan data (Censys) | https://github.com/christophetd/CloudFlair |
| Historical DNS + scan data | https://github.com/mrh0wl/Cloudmare (Cloudflare, Sucuri, Incapsula) |
| TLS certificate history | Check crt.sh for old certs with different IPs |
| DNS history | Whoxy, SecurityTrails historical DNS |

```bash
# CloudFlair — uses Censys data to find origin IPs
python cloudflare.py -d <domain>

# Cloudmare
python cloudmare.py <domain>
```
