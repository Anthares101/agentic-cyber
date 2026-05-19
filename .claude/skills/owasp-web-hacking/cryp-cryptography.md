# 4.9 Cryptography Testing (WSTG-CRYP)

Tests covering weak TLS, padding oracle, and weak/forbidden cipher use.

---

## WSTG-CRYP-01: Weak Transport Layer Security
**Legacy/Vulnerable Protocols:**
| Protocol/Feature | Attack |
|-----------------|--------|
| SSLv2 | DROWN |
| SSLv3 | POODLE |
| TLSv1.0 | BEAST |
| TLS compression | CRIME |
| RC4 | NOMORE |
| CBC mode | BEAST, Lucky 13 |
| EXPORT ciphers | FREAK |
| Weak DHE (<1024bit) | LOGJAM |
| NULL/Anonymous ciphers | MitM |

**Test Commands:**
```bash
nmap --script ssl-enum-ciphers -p 443 target.com
sslscan target.com
sslyze --regular target.com
testssl.sh target.com
openssl s_client -connect target.com:443 -ssl2
openssl s_client -connect target.com:443 -ssl3
```

**Certificate Requirements:**
- Key: ≥2048 bits RSA / 256 bits ECDSA
- Signature: SHA-256 minimum (not MD5/SHA-1)
- Not expired, max 398 days (post Sep 2020)
- Trusted CA, SAN matches hostname

---

## WSTG-CRYP-02: Padding Oracle
**Detection:** Encrypted values that are multiples of 8/16 bytes; distinct padding vs. other error responses.

**Test:** Modify last byte of second-to-last block; look for:
1. Correct decryption (rare)
2. Garbled data with generic exception
3. Padding error message (specific)

**Tools:** PadBuster, Bletchley, Poracle, python-paddingoracle, POET

---

## WSTG-CRYP-04: Weak Encryption
**Minimum Key Requirements:**
| Algorithm | Minimum |
|-----------|---------|
| RSA | 2048 bits |
| ECDSA/ECDH | 256 bits |
| AES | 128 bits |
| Diffie-Hellman | 2048 bits |
| HASH | SHA-256 |

**Forbidden Algorithms:** MD4, MD5, RC4, RC2, DES, Blowfish, SHA-1, ECB mode, 1024-bit RSA

**Password Hashing (Use):** PBKDF2 (>10,000 iterations), bcrypt, scrypt, Argon2

**Source Code Keywords (Java):**
```java
// Weak - flag these:
Cipher.getInstance("DES/CBC/PKCS5Padding")
Signature.getInstance("SHA1withRSA")
MessageDigest.getInstance("MD5")
// Secure:
Cipher.getInstance("AES/GCM/NoPadding")
RSA/ECB/OAEPWithSHA-256AndMGF1Padding
```
