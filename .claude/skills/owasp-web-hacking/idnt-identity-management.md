# 4.3 Identity Management Testing (WSTG-IDNT)

Tests focused on role definitions and account discovery.

---

## WSTG-IDNT-01: Test Role Definitions
**Objective:** Identify roles and test for unauthorized role switching.

**Methods:**
- Fuzz: `role=admin`, `isAdmin=True`, `Role: manager` in cookies/params
- Check hidden paths: `/admin`, `/mod`, `/backups`
- Try known usernames: `admin`, `backups`, `administrator`

**Tools:** Burp Autorize extension, ZAP Access Control Testing add-on

---

## WSTG-IDNT-04: Account Enumeration
**Objective:** Determine if valid usernames can be identified.

**Enumeration Signals:**
- Different error messages: "Invalid password" vs "User not found"
- Different response times (slower = user exists, external service call)
- Different HTTP response codes or lengths
- Password reset: "Email sent" vs "User not found"
- URL parameters revealing user existence: `?User=gooduser&Error=2`
- URI probing: `403 Forbidden` (user exists) vs `404 Not Found`

**Remediation:** Use identical generic messages for all auth failures.
