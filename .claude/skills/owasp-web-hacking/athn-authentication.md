# 4.4 Authentication Testing (WSTG-ATHN)

Tests covering credential transport, lockout, bypass, remember-me, browser cache, password policy, and password reset.

---

## WSTG-ATHN-01: Credentials over Encrypted Channel
```bash
# Force HTTP and check if creds still sent
curl -kis http://target.com/login
# Check: Set-Cookie should have Secure; attribute
# Check: Session cookies not sent over HTTP
```

---

## WSTG-ATHN-02: Default Credentials
**Common Usernames:** `admin`, `administrator`, `root`, `system`, `guest`, `operator`, `super`, `test`, `qa`
**Common Passwords:** `admin`, `password`, `pass123`, `password123`, `guest`, `[blank]`, `[same as username]`

**Resources:** CIRT.net, SecLists default passwords, Nikto2

**Gray-Box:** Check config files, source code, database for hard-coded credentials.

---

## WSTG-ATHN-03: Weak Lockout Mechanism
**Test Procedure:**
1. Test threshold: submit wrong password 3, 4, 5+ times
2. Test lockout duration: 5min, 10min, 15min
3. Test self-unlock: email link uniqueness, one-time use
4. CAPTCHA bypass:
   - Submit without solving CAPTCHA
   - Resubmit previously solved CAPTCHA response
   - Check if CAPTCHA only enforced client-side
   - Skip to step after CAPTCHA in multi-step process
   - Check mobile/API endpoints without CAPTCHA

---

## WSTG-ATHN-04: Bypass Authentication Schema
**Techniques:**
1. **Forced browsing:** Access protected pages directly without login
2. **Parameter modification:** `?authenticated=yes`, `?admin=true`
3. **Session ID prediction:** Linear or partially static cookie values
4. **SQL injection login bypass:** `' OR '1'='1` in username/password
5. **Type juggling (PHP):** `a:2:{s:11:"autologinid";b:1;s:6:"userid";s:1:"2";}` in serialized cookies (boolean `b:1` compared as TRUE to any string)

---

## WSTG-ATHN-05: Vulnerable Remember Password
**Check:**
- Credentials stored in `localStorage`/`sessionStorage` (not tokens)
- Long-lived tokens that never expire
- Tokens susceptible to CSRF/clickjacking for automatic injection

---

## WSTG-ATHN-06: Browser Cache Weaknesses
**Check Response Headers for Sensitive Pages:**
```
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

**Test:** Log in → view sensitive page → log out → press Back → can you see sensitive data?

**Browser Cache Locations:**
- Firefox: `~/.cache/mozilla/firefox/`
- Chrome: `~/.cache/google-chrome`
- IE/Edge: `C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache\`

---

## WSTG-ATHN-07: Weak Password Policy
**Evaluate:**
1. Minimum length (should be ≥8, ideally ≥12 chars)
2. Complexity requirements (upper, lower, digit, special)
3. Password history (last 8+ passwords)
4. Maximum age (NIST recommends NOT forcing regular expiry)
5. Common password prevention (`Password1`, `123456`)
6. Username prohibition in password

---

## WSTG-ATHN-08: Weak Security Question
**Evaluate:** Easily guessable answers (mother's maiden name from social media), limited question set (brute-forceable), answers stored in plaintext.

---

## WSTG-ATHN-09: Weak Password Reset
**Vulnerabilities:**
- Predictable reset tokens (sequential, time-based)
- Token doesn't expire after use
- Token valid for long time window
- No rate limiting on reset requests
- Host header injection in reset email link:
  ```
  Host: attacker.com  →  Reset link sent to attacker domain
  X-Forwarded-Host: attacker.com
  ```
