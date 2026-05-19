# 9. Google Dorks and Search Engine Recon

## 9.1 Dork References

| Resource | URL |
|----------|-----|
| Pentest-Tools Google Hacking | https://pentest-tools.com/information-gathering/google-hacking |
| haax.fr OSINT Dorks Cheatsheet | https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/ |

## 9.2 Common High-Value Dorks

```
site:<domain> filetype:pdf
site:<domain> filetype:xls OR filetype:xlsx
site:<domain> inurl:admin
site:<domain> inurl:login
site:<domain> inurl:wp-login
site:<domain> "index of"
site:<domain> intext:"password" filetype:txt
site:<domain> ext:env OR ext:cfg OR ext:conf
site:<domain> ext:sql
site:<domain> "DB_PASSWORD"
"<company>" filetype:pdf "confidential"
"<company>" inurl:dev OR inurl:staging OR inurl:test
```

## 9.3 Multi-Engine Strategy

> **Note:** Sometimes Brave, Bing, or DuckDuckGo index content that Google does not. Always try alternative search engines when Google results are exhausted.

- Brave: https://search.brave.com
- Bing: https://bing.com
- DuckDuckGo: https://duckduckgo.com
