# 4.1 Information Gathering (WSTG-INFO)

Passive and active enumeration of the target to map attack surface before testing vulnerabilities.

---

## WSTG-INFO-01: Search Engine Recon
**Objective:** Discover sensitive design/configuration information via search engines.

**Google Dork Operators:**
```
site:target.com                    # Limit to domain
inurl:admin site:target.com        # Admin paths
intitle:"index of" site:target.com # Directory listings
filetype:php site:target.com       # Specific extensions
filetype:env site:target.com       # .env files
filetype:bak site:target.com       # Backup files
cache:target.com                   # Cached content
intext:password site:target.com    # Passwords in body
```

**GHDB Categories:** Footholds, Sensitive Directories, Vulnerable Files, Error Messages, Files with Passwords, Admin Interfaces

**Tools:** Google, Bing, Shodan, DuckDuckGo, Wayback Machine, Bishop Fox GHDB

---

## WSTG-INFO-02: Fingerprint Web Server
**Objective:** Identify web server type/version to find version-specific vulnerabilities.

**Banner Grabbing:**
```bash
curl -I https://target.com
nc target.com 80
HEAD / HTTP/1.0

# Malformed request (reveals error page style)
GET / SANTA CLAUS/1.1
```

**Server Indicators:**
- Apache: `Date, Server, Last-Modified, ETag, Accept-Ranges, Content-Length, Connection, Content-Type`
- nginx: `Server, Date, Content-Type`
- `X-Powered-By:` header
- Default error page format

**Tools:** Netcraft, Nikto, Nmap (`nmap -sV`), WhatWeb, Wappalyzer

---

## WSTG-INFO-03: Review Webserver Metafiles
**Objective:** Identify paths/functionality from metadata files.

**Key Files to Check:**
```bash
curl https://target.com/robots.txt
curl https://target.com/sitemap.xml
curl https://target.com/security.txt
curl https://target.com/.well-known/security.txt
curl https://target.com/humans.txt
curl https://target.com/crossdomain.xml
curl https://target.com/clientaccesspolicy.xml
```

**robots.txt Disallow entries** often reveal hidden paths (admin panels, backup dirs, uploads).

---

## WSTG-INFO-04: Enumerate Applications on Webserver
**Objective:** Find all web applications on target server.

**Discovery Methods:**
```bash
# Port scan for non-standard HTTP ports
nmap -Pn -sT -sV -p0-65535 target.com

# DNS enumeration for virtual hosts
host -t ns target.com
host -l target.com ns1.target.com  # Zone transfer attempt
dig ns target.com +short

# Reverse IP lookup: ip:x.x.x.x (Bing), DomainTools
# Subdomain brute force
dnsrecon -d target.com
amass enum -d target.com
```

**Non-standard URLs:** `/webmail`, `/admin`, `/manager`, `/console`

---

## WSTG-INFO-05: Review Webpage Content for Information Leakage
**Objective:** Find sensitive info in HTML comments, JS, and source maps.

**What to Look For:**
```javascript
<!-- SQL queries, credentials, internal IPs in HTML comments -->
<!-- Use DB admin password: f@keP@a$$w0rD -->

// JS variables: API keys, internal routes, credentials
const myS3Credentials = { accessKeyId: "...", secretAcccessKey: "..." }
var conString = "tcp://postgres:1234@localhost/postgres";
```

**Source Maps:**
- `main.chunk.js` → check `main.chunk.js.map` for source paths/credentials
- Source maps expose full application structure

**Tools:** Browser DevTools, Burp Suite, Waybackurls, Google Maps API Scanner

---

## WSTG-INFO-06: Identify Application Entry Points
**Objective:** Map all input/injection points.

**Capture via Proxy:**
- All GET parameters (query string `?param=value`)
- All POST parameters (including hidden form fields)
- Cookie values
- Custom HTTP headers (`X-Custom-Header`, `debug: false`)
- JSON/XML body parameters

**Focus Points:**
- `Set-Cookie` in responses → session management
- 3xx redirects, 403, 500 errors → restricted areas
- `Server: BIG-IP` → load balancer (test multiple servers)

---

## WSTG-INFO-07: Map Execution Paths
**Objective:** Document all code paths and workflows.

**Approaches:** Path-based, Data Flow (taint analysis), Race condition testing

**Tools:** ZAP Spider, ZAP AJAX Spider, Burp Suite Spider, manual proxy walkthrough

---

## WSTG-INFO-08: Fingerprint Web Application Framework
**Objective:** Identify CMS/framework to target known vulnerabilities.

**Fingerprinting Vectors:**
| Signal | Check |
|--------|-------|
| HTTP Headers | `X-Powered-By:`, `X-Generator:` |
| Cookies | See table below |
| HTML source | `<meta name="generator">`, CSS/JS paths |
| File/folder structure | `/wp-admin/`, `/wp-content/`, `/joomla/` |
| File extensions | `.php`, `.aspx`, `.jsp` |
| Error messages | Stack traces reveal framework |

**Framework Cookie Names:**
| Framework | Cookie |
|-----------|--------|
| WordPress | `wp-settings` |
| Laravel | `laravel_session` |
| Django | `django` |
| CakePHP | `cakephp` |
| TYPO3 | `fe_typo_user` |
| phpBB | `phpbb3_` |
| DotNetNuke | `DotNetNukeAnonymous` |

**HTML Markers:**
| CMS | Marker |
|-----|--------|
| WordPress | `<meta name="generator" content="WordPress 3.9.2">` |
| Drupal | `<meta name="Generator" content="Drupal 7">` |
| Joomla | `<meta name="generator" content="Joomla!">` |
| ASP.NET | `__VIEWSTATE` |

**Tools:** WhatWeb, Wappalyzer, dirbusting (`gobuster`, `ffuf`, `feroxbuster`)

---

## WSTG-INFO-10: Map Application Architecture
**Objective:** Understand load balancers, reverse proxies, CDNs, WAFs.

**Detection Indicators:**
- Reverse proxy: Varying server headers, mod_security error pages
- Load balancer: `BIGipServer` cookie prefix (F5), inconsistent `Date` headers
- WAF: Blocked requests return different pages than expected 404s
- App server: `JSESSIONID` (J2EE), URL rewriting for sessions
