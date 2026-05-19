# 4.2 Configuration & Deployment Management Testing (WSTG-CONF)

Tests focused on misconfigurations in the underlying server, platform, and deployment topology.

---

## WSTG-CONF-01: Network Infrastructure Configuration
**Objective:** Identify vulnerable server components, unpatched software, misconfigured services.

**Test:** Compare server versions against CVE databases; check vendor advisories.

---

## WSTG-CONF-02: Application Platform Configuration
**Objective:** Find default files, debug code, poor logging config.

**Check for Default/Sample Files:**
```bash
nikto -h https://target.com
# Also check: /test/, /sample/, /demo/, /example/
```

**Logging Issues:** Sensitive data in logs, logs accessible via web, log injection, no log rotation.

**Critical Configs (IIS):** Do not grant non-admin accounts access to `applicationHost.config`, `redirection.config`.

---

## WSTG-CONF-03: File Extensions Handling
**Objective:** Identify dangerous file extensions that expose source or bypass restrictions.

**Dangerous Extensions:**
```
.asa, .inc, .config          → never serve
.bak, .old, .~, .swp         → backup files (source disclosure)
.zip, .tar, .gz, .tgz, .rar  → archive files
.java, .cs, .py, .rb         → source code
```

**Windows 8.3 Bypass:**
- `file.phtml` → processed as PHP
- `shell.phPWND` → upload bypass (becomes `SHELL~1.PHP`)
- `FILE~1.PHT` → served but not processed

---

## WSTG-CONF-04: Backup and Unreferenced Files
**Objective:** Find forgotten backup files exposing source code/credentials.

**Common Patterns to Fuzz:**
```
login.asp    → login.asp.old, login.asp.bak, login.asp~
config.php   → config.php.bak, config.php.orig, config.php.swp
index.php    → index.php-, index.php.1, copy_of_index.php
             → "Copy of index.php" (Windows)
/snapshots/, /.snapshot/monthly.1/
```

**Blind Guessing Script:**
```bash
while read url; do
    echo -e "GET /$url HTTP/1.0\nHost: target.com\n" | nc target.com 80 | head -1
done < wordlist.txt
```

**Response Codes of Interest:** 200 (found), 301/302 (redirect), 401 (auth required), 403 (exists but forbidden), 500 (server error)

**Tools:** Nikto, Gobuster, feroxbuster, dirbuster

---

## WSTG-CONF-05: Admin Interface Enumeration
**Objective:** Discover hidden administrative interfaces.

**Common Admin Paths:**
```
/admin, /admin/, /administrator, /admin.php
/wp-admin/, /wp-login.php          (WordPress)
/phpmyadmin/, /mysqladmin/         (PHP/MySQL)
/manager/html                      (Tomcat)
/console                           (JBoss)
/admin.dll, /admin.exe             (FrontPage)
/AdminMain, /AdminClients          (WebLogic)
:8080/manager, :9090/              (Alternative ports)
```

**Techniques:**
- Parameter tampering: `?admin=true`, `?role=admin`
- Cookie manipulation: `useradmin=0` → `useradmin=1`
- Source code comments revealing admin links
- Default password lists (CIRT, SecLists)

**Tools:** OWASP ZAP Forced Browse, THC-HYDRA, FuzzDB

---

## WSTG-CONF-06: HTTP Methods
**Objective:** Find dangerous enabled methods (PUT, DELETE, TRACE) and bypass via method override.

**Enumerate Methods:**
```bash
nmap -p 443 --script http-methods --script-args http-methods.url-path='/index.php' target.com
curl -X OPTIONS https://target.com -v
```

**Test PUT (File Upload):**
```
PUT /test.html HTTP/1.1
Host: target.com
<html>HTTP PUT Enabled</html>
```

**Access Control Bypass via Unknown Methods:**
```bash
ncat target.com 80
HEAD /admin HTTP/1.1
Host: target.com
# Returns 200? → auth bypass
BILBAO /admin HTTP/1.1  # Arbitrary methods sometimes bypass ACL
```

**TRACE XST Test:**
```bash
ncat target.com 80
TRACE / HTTP/1.1
Host: target.com
Attack: <script>prompt()</script>
```

**HTTP Method Override Headers:**
```
X-HTTP-Method: DELETE
X-HTTP-Method-Override: DELETE
X-Method-Override: DELETE
```

**Remediation:** Allow only required methods; disable TRACE globally.

---

## WSTG-CONF-07: HTTP Strict Transport Security (HSTS)
**Check:**
```bash
curl -s -D- https://target.com | grep -i strict
# Expect: Strict-Transport-Security: max-age=31536000; includeSubDomains
```

---

## WSTG-CONF-08: RIA Cross Domain Policy
**Check Files:**
```
/crossdomain.xml
/clientaccesspolicy.xml
```

**Dangerous Config (Too Permissive):**
```xml
<allow-access-from domain="*" secure="false"/>
<allow-http-request-headers-from domain="*" headers="*" secure="false"/>
```

---

## WSTG-CONF-10: Subdomain Takeover
**Objective:** Identify subdomains pointing to non-existent/unclaimed external services.

**Signs of Vulnerability:**
- CNAME points to domain returning `NXDOMAIN`
- DNS response: `NXDOMAIN`, `SERVFAIL`, `REFUSED`
- GitHub Pages: 404 "File not found" with GitHub branding
- Heroku/Azure/AWS: service-specific unclaimed pages

**Testing:**
```bash
dnsrecon -d target.com
dig CNAME subdomain.target.com
whois <IP> | grep OrgName  # Identify provider
dig ns target.com +short    # Check NS expiry
```

**Tools:** dnsrecon, Sublist3r, amass, theHarvester, recon-ng

---

## WSTG-CONF-11: Cloud Storage Misconfiguration
**Test S3 Buckets:**
```bash
# Read
curl -X GET https://bucket-name.s3.us-east-1.amazonaws.com/file.txt

# List (if public)
aws s3 ls s3://bucket-name

# Upload (tests write access)
curl -X PUT -d 'test' 'https://bucket-name.s3.amazonaws.com/test.txt'
aws s3 cp test.txt s3://bucket-name/test.txt
```

**S3 URL Formats:**
- Virtual-hosted: `https://bucket-name.s3.region.amazonaws.com/key`
- Path-style: `https://s3.region.amazonaws.com/bucket-name/key`

**Tools:** AWS CLI, flAWS 2 (training), S3Scanner
