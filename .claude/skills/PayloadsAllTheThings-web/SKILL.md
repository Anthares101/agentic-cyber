---
name: PayloadsAllTheThings-web
description: Use when testing web applications for security vulnerabilities — provides payloads, bypass techniques, and exploitation methodology for XSS, SQL injection, SSTI, SSRF, XXE, LFI, deserialization, JWT/OAuth/SAML, CSRF, prototype pollution, NoSQL, GraphQL, LDAP, XPATH, upload bypass, IDOR, business logic, race conditions, web cache deception, request smuggling, CSP bypass, WAF bypass, and all other web attack classes. Use when looking up specific payloads, enumeration queries, or exploitation chains for any web vulnerability class.
---

# PayloadsAllTheThings Web Security Reference

Comprehensive web application security payload reference based on PayloadsAllTheThings.

## Supporting Reference Files

| File | Coverage |
|------|----------|
| [xss-reference.md](xss-reference.md) | XSS (reflected/stored/DOM/blind/mutation), filter bypass, polyglots, CSP bypass, WAF bypass, AngularJS CSTI |
| [sqli-reference.md](sqli-reference.md) | SQL Injection: MySQL, MSSQL, PostgreSQL, Oracle, SQLite, BigQuery; SQLmap usage |
| [ssti-reference.md](ssti-reference.md) | Server-Side Template Injection: Python (Jinja2/Django/Mako/Tornado), Java (Freemarker/Velocity/SpEL/OGNL/Pebble/Groovy), PHP (Twig/Smarty/Blade/Latte), JS (Handlebars/Pug/Lodash), Ruby (ERB/HAML/Slim), ASP.NET Razor |
| [injection-reference.md](injection-reference.md) | Command injection, XXE, SSRF (+ cloud metadata), LFI/RFI (PHP wrappers, LFI-to-RCE), NoSQL, GraphQL, LDAP, XPATH, SSI/ESI, XSLT, LaTeX, CSV, HTTP param pollution, CRLF |
| [auth-reference.md](auth-reference.md) | JWT attacks, OAuth misconfig, SAML injection, CSRF, MFA bypass, account takeover, open redirect, CORS |
| [deserialization-reference.md](deserialization-reference.md) | Insecure deserialization: PHP, Java (ysoserial), Python (pickle/PyYAML), Ruby (Marshal/YAML), Node.js, .NET |
| [client-side-reference.md](client-side-reference.md) | DOM clobbering, XS-Leak, CSS injection, WebSockets/CSWSH, clickjacking, tabnabbing, CSPT, prototype pollution |
| [misc-reference.md](misc-reference.md) | IDOR, mass assignment, business logic, race conditions, web cache deception, request smuggling, upload bypass, type juggling, API key leaks, dependency confusion, zip slip, encoding transformations, insecure randomness, DNS rebinding, headless browser, Java RMI, reverse proxy misconfig, virtual hosts, brute force/rate limit |

## Quick Decision Matrix

| You See... | Attack to Try First |
|------------|---------------------|
| User input reflected in page | XSS → see xss-reference.md |
| Numeric/string param in DB query | SQLi → see sqli-reference.md |
| Template syntax `{{`, `${`, `<#` | SSTI → see ssti-reference.md |
| URL param accepted by server | SSRF → see injection-reference.md |
| XML parsed by app | XXE → see injection-reference.md |
| File path in param | LFI/RFI → see injection-reference.md |
| `cmd=`, `exec=`, backticks | Command injection → see injection-reference.md |
| JWT token in cookies/header | JWT attacks → see auth-reference.md |
| OAuth flow with redirect_uri | OAuth misconfig → see auth-reference.md |
| SAML assertion | SAML injection → see auth-reference.md |
| State-changing GET request | CSRF → see auth-reference.md |
| Serialized object in cookie/param | Deserialization → see deserialization-reference.md |
| NoSQL DB (MongoDB) | NoSQL injection → see injection-reference.md |
| GraphQL endpoint | GraphQL injection → see injection-reference.md |
| Object/resource ID in URL | IDOR → see misc-reference.md |
| Multiple user params accepted | Mass assignment → see misc-reference.md |
| Time/quantity-sensitive operation | Race condition → see misc-reference.md |
| File upload feature | Upload bypass → see misc-reference.md |
| PHP loose comparison | Type juggling → see misc-reference.md |
| `window.opener`, `_blank` links | Tabnabbing → see client-side-reference.md |
| window.__proto__, URL params | Prototype pollution → see client-side-reference.md |

## General Testing Methodology

1. **Recon**: Map all entry points (params, headers, cookies, JSON body, file uploads, WebSockets)
2. **Identify tech stack**: DBMS, template engine, language/framework, serialization format
3. **Apply relevant payloads** from reference files above
4. **Chain findings**: SSRF → cloud metadata → credentials; LFI → log poisoning → RCE; XSS → session hijack → account takeover
5. **Escalate**: from read to write, from low-priv to admin, from user to RCE

## Tools Quick Reference

| Category | Tool |
|----------|------|
| SQLi | sqlmap, ghauri |
| SSTI | tplmap, sstimap |
| SSRF | ssrfmap, gopherus |
| LFI | fimap |
| XSS | dalfox, XSStrike |
| Fuzzing | ffuf, feroxbuster |
| Param discovery | arjun, x8, param-miner |
| Secrets | trufflehog, nuclei |
| Deserialization | ysoserial, phpggc, ysoserial.net |
| JWT | jwt_tool |
| API | nuclei, postman |
