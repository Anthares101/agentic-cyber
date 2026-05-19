# Cross-cutting Reference

Use this file when you need payload encoding helpers, tool selection, or a full WSTG test ID lookup.

---

## Quick Reference: Payload Encoding

**Browser Console Encoding:**
```javascript
btoa("string")                        // Base64 encode
atob("string")                        // Base64 decode
encodeURIComponent("string")          // URL encode
decodeURIComponent("string")          // URL decode
escape("string")                      // HTML encode
```

**XSS Encoding Bypasses:**
```
String.fromCharCode(88,83,83)         // Char codes
&#x58;&#x53;&#x53;                    // Hex HTML entities
&#88;&#83;&#83;                       // Decimal HTML entities
XSS                    // Unicode escapes
+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-  // UTF-7
```

---

## Testing Tools Reference

| Category | Tools |
|----------|-------|
| Proxy/Intercept | Burp Suite, OWASP ZAP, Caido |
| Spidering | ZAP Spider, Burp Spider, Gospider, Katana |
| Directory Brute | Gobuster, ffuf, feroxbuster, dirbuster |
| Subdomain Enum | Amass, Sublist3r, dnsrecon, theHarvester |
| Vuln Scanning | Nikto, Nessus, OpenVAS |
| SQLi | sqlmap, Havij, ghauri |
| XSS | XSSHunter, Dalfox, kxss |
| SSTI | Tplmap, Backslash Powered Scanner |
| SSRF | SSRFmap, interactsh, Burp Collaborator |
| Command Injection | Commix |
| XXE | XXEinjector, Burp extension |
| Fuzzing | wfuzz, ffuf, Burp Intruder |
| Secrets | TruffleHog, gitleaks, grep patterns |
| SSL/TLS | testssl.sh, sslscan, sslyze, O-Saft |
| Padding Oracle | PadBuster, Bletchley, Poracle |
| Auth Brute | THC-Hydra, Medusa, Burp Intruder |
| Port Scanning | Nmap, Masscan, RustScan |
| Fingerprinting | WhatWeb, Wappalyzer, Netcraft |
| GraphQL | InQL, GraphQL Raider, graphqlmap |
| WebSocket | ZAP, Simple WebSocket Client |

---

## WSTG Test ID Reference

| ID | Test Name |
|----|-----------|
| WSTG-INFO-01 | Search Engine Recon |
| WSTG-INFO-02 | Fingerprint Web Server |
| WSTG-INFO-03 | Review Metafiles |
| WSTG-INFO-04 | Enumerate Applications |
| WSTG-INFO-05 | Review Webpage Content |
| WSTG-INFO-06 | Identify Entry Points |
| WSTG-INFO-07 | Map Execution Paths |
| WSTG-INFO-08 | Fingerprint Framework |
| WSTG-INFO-10 | Map Architecture |
| WSTG-CONF-01 | Network Infrastructure Config |
| WSTG-CONF-02 | Application Platform Config |
| WSTG-CONF-03 | File Extension Handling |
| WSTG-CONF-04 | Backup and Unreferenced Files |
| WSTG-CONF-05 | Admin Interface Enumeration |
| WSTG-CONF-06 | HTTP Methods |
| WSTG-CONF-07 | HTTP Strict Transport Security |
| WSTG-CONF-08 | RIA Cross Domain Policy |
| WSTG-CONF-09 | File Permissions |
| WSTG-CONF-10 | Subdomain Takeover |
| WSTG-CONF-11 | Cloud Storage |
| WSTG-IDNT-01 | Role Definitions |
| WSTG-IDNT-02 | User Registration |
| WSTG-IDNT-03 | Account Provisioning |
| WSTG-IDNT-04 | Account Enumeration |
| WSTG-IDNT-05 | Username Policy |
| WSTG-ATHN-01 | Credentials Over Encrypted Channel |
| WSTG-ATHN-02 | Default Credentials |
| WSTG-ATHN-03 | Weak Lockout |
| WSTG-ATHN-04 | Bypass Authentication |
| WSTG-ATHN-05 | Remember Password |
| WSTG-ATHN-06 | Browser Cache |
| WSTG-ATHN-07 | Weak Password Policy |
| WSTG-ATHN-08 | Security Questions |
| WSTG-ATHN-09 | Password Reset |
| WSTG-ATHN-10 | Alternative Channel Auth |
| WSTG-ATHZ-01 | Directory Traversal |
| WSTG-ATHZ-02 | Bypass Authorization |
| WSTG-ATHZ-03 | Privilege Escalation |
| WSTG-ATHZ-04 | IDOR |
| WSTG-SESS-01 | Session Management Schema |
| WSTG-SESS-02 | Cookie Attributes |
| WSTG-SESS-03 | Session Fixation |
| WSTG-SESS-04 | Exposed Session Variables |
| WSTG-SESS-05 | CSRF |
| WSTG-SESS-06 | Logout Functionality |
| WSTG-SESS-07 | Session Timeout |
| WSTG-SESS-08 | Session Puzzling |
| WSTG-SESS-09 | Session Hijacking |
| WSTG-INPV-01 | Reflected XSS |
| WSTG-INPV-02 | Stored XSS |
| WSTG-INPV-03 | HTTP Verb Tampering |
| WSTG-INPV-04 | HTTP Parameter Pollution |
| WSTG-INPV-05 | SQL Injection (all DBs + NoSQL + ORM) |
| WSTG-INPV-06 | LDAP Injection |
| WSTG-INPV-07 | XML Injection / XXE |
| WSTG-INPV-08 | SSI Injection |
| WSTG-INPV-09 | XPath Injection |
| WSTG-INPV-10 | IMAP/SMTP Injection |
| WSTG-INPV-11 | Code Injection / LFI / RFI |
| WSTG-INPV-12 | Command Injection |
| WSTG-INPV-13 | Format String Injection |
| WSTG-INPV-14 | Incubated Vulnerabilities |
| WSTG-INPV-15 | HTTP Splitting/Smuggling |
| WSTG-INPV-17 | Host Header Injection |
| WSTG-INPV-18 | Server-Side Template Injection (SSTI) |
| WSTG-INPV-19 | Server-Side Request Forgery (SSRF) |
| WSTG-ERRH-01 | Improper Error Handling |
| WSTG-CRYP-01 | Weak TLS |
| WSTG-CRYP-02 | Padding Oracle |
| WSTG-CRYP-03 | Unencrypted Sensitive Data |
| WSTG-CRYP-04 | Weak Encryption |
| WSTG-BUSL-01 | Business Logic Data Validation |
| WSTG-BUSL-02 | Forged Requests |
| WSTG-BUSL-03 | Integrity Checks |
| WSTG-BUSL-04 | Process Timing |
| WSTG-BUSL-05 | Function Use Limits |
| WSTG-BUSL-06 | Workflow Circumvention |
| WSTG-BUSL-07 | Application Misuse Defenses |
| WSTG-BUSL-08 | Unexpected File Upload |
| WSTG-BUSL-09 | Malicious File Upload |
| WSTG-CLNT-01 | DOM XSS |
| WSTG-CLNT-02 | JavaScript Execution |
| WSTG-CLNT-03 | HTML Injection |
| WSTG-CLNT-04 | Client-side URL Redirect |
| WSTG-CLNT-05 | CSS Injection |
| WSTG-CLNT-06 | Client-side Resource Manipulation |
| WSTG-CLNT-07 | CORS |
| WSTG-CLNT-08 | Cross-Site Flashing |
| WSTG-CLNT-09 | Clickjacking |
| WSTG-CLNT-10 | WebSockets |
| WSTG-CLNT-11 | Web Messaging |
| WSTG-CLNT-12 | Browser Storage |
| WSTG-CLNT-13 | XSSI |
| WSTG-APIT-01 | GraphQL |
