# 4.8 Error Handling Testing (WSTG-ERRH)

Tests covering improper error handling and information leakage through error responses.

---

## WSTG-ERRH-01: Improper Error Handling
**Force Errors:**
- Request non-existent files → 404 details
- Access forbidden directories → 403 details
- Send malformed HTTP (wrong version, huge path, broken headers)
- Input type mismatches (string where int expected, XML/JSON syntax errors)
- Close bracket in JSON body: `{"param": "value"`

**Error Signals to Look For:**
- Stack traces with file paths and line numbers
- Internal IP addresses
- Version strings
- Database query fragments
- Technology/framework disclosure
- Debug output left enabled
