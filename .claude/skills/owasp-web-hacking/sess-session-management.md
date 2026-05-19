# 4.6 Session Management Testing (WSTG-SESS)

Tests covering token schema, cookie attributes, fixation, exposed variables, CSRF, logout, timeout, session puzzling, and hijacking.

---

## WSTG-SESS-01: Session Management Schema
**Analyze Tokens:**
```bash
# Collect multiple tokens and analyze entropy/patterns
# Use Burp Suite Sequencer for statistical analysis
```

**Token Properties to Check:**
- Sufficient randomness (128+ bits of entropy)
- Not based on predictable data (time, username, sequential ID)
- Unique per session
- Sufficient length

---

## WSTG-SESS-02: Cookie Attributes
**Required Attributes:**
```
Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Domain=.target.com
```

| Attribute | Purpose | Absence Risk |
|-----------|---------|-------------|
| `Secure` | Only HTTPS | Transmitted over HTTP |
| `HttpOnly` | No JS access | XSS steals cookie |
| `SameSite=Strict` | No cross-site | CSRF attacks |
| `Path=/` | Scope limit | Cross-path access |
| `Expires/Max-Age` | Lifetime | Persistent sessions |

---

## WSTG-SESS-03: Session Fixation
**Test:**
1. Get session ID before login (e.g., from unauthenticated visit)
2. Log in using that session ID
3. Check if session ID changes after login (it must)
4. If same session ID → fixation vulnerability

**Attack:** Attacker plants known session ID → victim logs in → attacker uses same ID

---

## WSTG-SESS-04: Exposed Session Variables
**Check:** Session IDs in URLs (`?PHPSESSID=abc`), in Referer headers, in browser history, in server logs.

---

## WSTG-SESS-05: CSRF (Cross-Site Request Forgery)
**Test:** Attempt to perform state-changing actions from a different origin.

**CSRF PoC Template:**
```html
<html>
<body onload="document.forms[0].submit()">
<form action="https://target.com/api/changePassword" method="POST">
  <input type="hidden" name="newPassword" value="hacked123">
  <input type="hidden" name="confirm" value="hacked123">
</form>
</body>
</html>
```

**Bypass Techniques:**
- Remove CSRF token entirely
- Send empty CSRF token
- Use CSRF token from your own session in another account's request
- Change POST to GET
- Change Content-Type to `text/plain` or `application/x-www-form-urlencoded`

**Defenses to Verify:**
- Synchronizer token pattern (per-form random token)
- Double Submit Cookie
- SameSite=Strict cookies
- Origin/Referer header validation
- Custom request headers (`X-Requested-With`)

---

## WSTG-SESS-06: Logout Functionality
**Check:**
- Session token invalidated server-side (not just deleted client-side)
- Can old session ID be reused after logout?
- All tokens invalidated (remember-me, API tokens)
- Return to secure pages via Back button after logout

---

## WSTG-SESS-07: Session Timeout
**Test:**
- Leave session idle 10, 20, 30 minutes → test if still active
- Absolute timeout (maximum session duration regardless of activity)
- Idle timeout vs absolute timeout

---

## WSTG-SESS-08: Session Puzzling (Session Variable Overloading)
**Objective:** Exploit shared session variables across different application functions with conflicting purposes.

**Example:** Variable `userId` used for both password reset flow and authentication → trick app by interleaving flows.

---

## WSTG-SESS-09: Session Hijacking
**Attack Vectors:**
- XSS to steal cookies (mitigated by HttpOnly)
- Network sniffing (mitigated by HTTPS + Secure)
- Predictable session IDs
- Session fixation
- Browser cache/history exposure
