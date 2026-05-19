# 7. Service and Port Information (Passive)

Avoid active port scanning — use Shodan's already-collected data.

## 7.1 Shodan Bulk Host Lookup

Query Shodan for all known IPs to get open ports, banners, and service versions:
```bash
while read line; do
  shodan host $line
  echo "--------------------"
done < ips.txt > results.txt
```

Use Shodan filters passively:
```
org:"<Organization Name>"
hostname:"target.com"
ssl:"target.com"
net:<CIDR>
```
