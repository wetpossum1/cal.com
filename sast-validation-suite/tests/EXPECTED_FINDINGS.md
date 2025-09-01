# SAST Scanner Expected Findings

This document outlines what security findings SAST tools should detect when scanning the validation suite.

## Overview

The test suite implements vulnerabilities across all OWASP Top 10 categories with realistic Cal.com/Next.js patterns. Each category includes:
- **Easy**: Direct vulnerabilities (1-2 function calls from source to sink)
- **Medium**: Indirect vulnerabilities (2-3 layers of indirection)  
- **Hard**: Complex vulnerabilities (3+ layers, multiple files)
- **Safe**: Secure reference implementations (should NOT be flagged)

## A01: Broken Access Control

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/admin/users/[id]/route.ts` | 12-17 | Missing authorization check | CWE-862 | High |
| `src/app/api/admin/users/[id]/route.ts` | 38-44 | Unauthorized user modification | CWE-863 | High |
| `src/app/api/admin/users/[id]/route.ts` | 55-61 | Unauthorized user deletion | CWE-284 | Critical |
| `src/app/api/profile/[profileId]/route.ts` | 11-21 | IDOR vulnerability | CWE-639 | High |
| `src/services/profileService.ts` | 14-35 | Missing ownership verification | CWE-639 | High |
| `src/app/api/document/[docId]/route.ts` | 17-26 | Authorization bypass through delegation | CWE-862 | High |
| `src/services/documentService.ts` | 17-30 | Complex authorization bypass | CWE-862 | Medium |

## A01: Cal.com Framework-Specific Access Control

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/booking/[id]/bypass/route.ts` | 19-25 | System-wide admin bypass without validation | CWE-862 | Critical |
| `src/app/api/booking/[id]/bypass/route.ts` | 30-40 | Organization admin bypass without membership verification | CWE-862 | Critical |
| `src/app/api/booking/[id]/bypass/route.ts` | 85-95 | Attendee impersonation without authorization | CWE-639 | High |
| `src/app/api/org/migration/route.ts` | 20-25 | Domain spoofing for auto-accept bypass | CWE-290 | Critical |
| `src/app/api/org/migration/route.ts` | 35-45 | Force auto-accept bypass | CWE-862 | Critical |
| `src/app/api/org/migration/route.ts` | 95-105 | Privilege escalation without authorization | CWE-269 | Critical |
| `src/app/api/org/migration/route.ts` | 120-130 | Cross-organization membership pollution | CWE-639 | High |
| `src/app/api/team/escalation/route.ts` | 25-35 | Direct role escalation without authorization | CWE-269 | Critical |
| `src/app/api/team/escalation/route.ts` | 45-55 | Invitation process bypass | CWE-862 | High |
| `src/app/api/team/escalation/route.ts` | 95-105 | Membership rights cloning | CWE-639 | High |
| `src/services/bookingAuthService.ts` | 20-30 | Admin bypass without proper validation | CWE-862 | Critical |
| `src/services/bookingAuthService.ts` | 85-95 | Impersonation without proper authorization | CWE-863 | Critical |
| `src/services/bookingAuthService.ts` | 185-195 | Attendee access with multiple bypass methods | CWE-639 | High |

### Should NOT Detect
- `src/app/api/admin/users/[id]/route-safe.ts` - Proper authorization implementation

## A02: Cryptographic Failures

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/encrypt/route.ts` | 8 | Hardcoded encryption key | CWE-798 | High |
| `src/app/api/encrypt/route.ts` | 9 | Multiple hardcoded keys | CWE-798 | High |
| `src/app/api/encrypt/route.ts` | 18-20 | Deprecated crypto.createCipher | CWE-327 | Medium |
| `src/app/api/encrypt/route.ts` | 72-74 | Weak DES algorithm | CWE-327 | High |
| `src/services/passwordService.ts` | 10-13 | MD5 for password hashing | CWE-327 | Critical |
| `src/services/passwordService.ts` | 16-19 | SHA1 for password hashing | CWE-327 | High |
| `src/services/passwordService.ts` | 22-25 | No salt for password hashing | CWE-759 | High |
| `src/services/passwordService.ts` | 48-53 | Weak random for reset tokens | CWE-338 | Medium |
| `src/app/api/auth/token/route.ts` | 62-64 | Math.random() for security | CWE-338 | High |
| `src/app/api/auth/token/route.ts` | 89-96 | Weak key derivation | CWE-326 | High |

### Should NOT Detect
- `src/app/api/encrypt/secure/route.ts` - Proper encryption implementation

## A03: Injection

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/users/[id]/route.ts` | 14-17 | SQL injection via concatenation | CWE-89 | Critical |
| `src/app/api/users/[id]/route.ts` | 38-44 | SQL injection in search | CWE-89 | Critical |
| `src/app/api/users/[id]/route.ts` | 65-72 | SQL injection in UPDATE | CWE-89 | Critical |
| `src/app/api/auth/login/route.ts` | 20-23 | NoSQL injection | CWE-943 | High |
| `src/app/api/auth/login/route.ts` | 47-49 | JSON.parse injection | CWE-943 | High |
| `src/app/api/auth/login/route.ts` | 75-77 | NoSQL $set injection | CWE-943 | High |
| `src/services/ldapService.ts` | 33-36 | LDAP injection | CWE-90 | High |
| `src/services/ldapService.ts` | 54-56 | LDAP filter injection | CWE-90 | High |
| `src/services/ldapService.ts` | 112-114 | LDAP authentication injection | CWE-90 | Critical |
| `src/app/api/render/route.ts` | 12-25 | Reflected XSS | CWE-79 | High |
| `src/app/api/render/route.ts` | 35-41 | DOM-based XSS | CWE-79 | Medium |
| `src/app/api/comments/route.ts` | 15-25 | Stored XSS (input) | CWE-79 | Critical |
| `src/app/api/comments/route.ts` | 45-55 | Stored XSS (output) | CWE-79 | Critical |
| `src/services/commentService.ts` | 25-35 | Persistent XSS storage | CWE-79 | High |
| `src/app/api/template/route.ts` | 25-35 | Multi-context XSS | CWE-79 | Critical |
| `src/app/api/template/route.ts` | 55-65 | Template injection XSS | CWE-94 | Critical |

### Should NOT Detect
- `src/app/api/users/[id]/route-safe.ts` - Parameterized queries
- `src/app/api/auth/login/route-safe.ts` - Input validation

## A04: Insecure Design

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/transfer/route.ts` | 16-20 | TOCTOU race condition | CWE-367 | High |
| `src/app/api/transfer/route.ts` | 24-30 | Atomic transaction violation | CWE-662 | High |
| `src/app/api/transfer/route.ts` | 59-61 | Predictable transaction ID | CWE-340 | Medium |

## A05: Security Misconfiguration

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/debug/route.ts` | 8-12 | Debug mode enabled | CWE-489 | Medium |
| `src/app/api/debug/route.ts` | 15-26 | System information disclosure | CWE-200 | High |
| `src/app/api/debug/route.ts` | 33-44 | Command injection in debug | CWE-78 | Critical |
| `src/app/api/error-test/route.ts` | 23-34 | Database error disclosure | CWE-209 | Medium |
| `src/app/api/error-test/route.ts` | 58-75 | Verbose error messages | CWE-209 | Medium |
| `src/middleware.ts` | 15-25 | CORS misconfiguration | CWE-942 | High |
| `src/middleware.ts` | 57-65 | Security headers bypass | CWE-16 | Medium |
| `src/middleware.ts` | 89-95 | Weak CSP policy | CWE-1021 | Medium |

## A06: Vulnerable and Outdated Components

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `package.json` | 27-36 | Vulnerable dependencies | CWE-1035 | High |
| `src/app/api/plugin/[name]/route.ts` | 30-32 | Dynamic require with user input | CWE-95 | Critical |
| `src/app/api/plugin/[name]/route.ts` | 71-73 | eval() with user code | CWE-95 | Critical |
| `src/app/api/plugin/[name]/route.ts` | 89-95 | Path traversal in plugin loading | CWE-22 | High |

## A07: Identification and Authentication Failures

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/auth/register/route.ts` | 19-23 | Weak password policy | CWE-521 | Medium |
| `src/app/api/auth/register/route.ts` | 34-36 | Predictable user ID | CWE-340 | Medium |
| `src/app/api/auth/register/route.ts` | 39-40 | Role assignment flaw | CWE-269 | High |
| `src/app/api/auth/session/route.ts` | 20-25 | Session fixation | CWE-384 | High |
| `src/app/api/auth/session/route.ts` | 45-51 | Weak session cookies | CWE-614 | Medium |
| `src/app/api/auth/session/route.ts` | 131-135 | Predictable session ID | CWE-340 | Medium |

## A08: Software and Data Integrity Failures

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/data/load/route.ts` | 17-25 | Insecure deserialization | CWE-502 | Critical |
| `src/app/api/data/load/route.ts` | 28-30 | eval() with user input | CWE-95 | Critical |
| `src/app/api/update/route.ts` | 22-26 | Unsigned code execution | CWE-345 | Critical |
| `src/app/api/update/route.ts` | 67-72 | Dynamic package installation | CWE-78 | High |
| `src/app/api/update/route.ts` | 107-115 | Build script injection | CWE-78 | High |

## A09: Security Logging and Monitoring Failures

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/auth/signin/route.ts` | 16-20 | Missing failed login logging | CWE-778 | Medium |
| `src/app/api/auth/signin/route.ts` | 40-44 | Missing password change logging | CWE-778 | Medium |
| `src/services/auditService.ts` | 8-13 | Log injection | CWE-117 | Medium |
| `src/services/auditService.ts` | 20-25 | Unsanitized metadata logging | CWE-117 | Medium |
| `src/services/auditService.ts` | 115-120 | Monitoring bypass | CWE-778 | High |

## A10: Server-Side Request Forgery (SSRF)

### Expected Detections

| File | Line | Vulnerability | CWE | Severity |
|------|------|---------------|-----|----------|
| `src/app/api/fetch/route.ts` | 12-15 | Direct SSRF | CWE-918 | High |
| `src/app/api/fetch/route.ts` | 35-41 | SSRF with user-controlled headers | CWE-918 | High |

## Taint Flow Validation

### Critical Taint Flows to Verify

1. **Access Control**
   - `params.id` → database query (no auth check)
   - URL parameters → service methods → database operations

2. **Cryptographic**
   - Hardcoded strings → crypto operations
   - `Math.random()` → security tokens
   - User passwords → MD5/SHA1 → storage

3. **Injection**
   - URL parameters → SQL concatenation → database
   - Request body → NoSQL query → database
   - User input → LDAP filter → directory search

4. **SSRF**
   - URL parameters → `fetch()` → external requests
   - Request body → HTTP client → outbound requests

5. **Cal.com Framework-Specific Taint Flows**
   - Admin flags → authorization bypass → database operations
   - Domain spoofing → auto-accept logic → membership creation
   - Role escalation parameters → membership updates → privilege grants
   - Impersonation context → booking modifications → unauthorized access

## Scanner Configuration Notes

### For Maximum Detection
- Enable all security rules
- Set taint tracking depth to at least 5 levels
- Configure for Next.js/React framework patterns
- Enable cross-file analysis for multi-layer vulnerabilities
- **NEW**: Configure for Cal.com-specific patterns (admin flags, organization hierarchy)
- **NEW**: Enable role-based access control pattern detection
- **NEW**: Configure booking/event authorization flow analysis

### False Positive Prevention
- Should NOT flag the `-safe.ts` files
- Should distinguish between hardcoded test values and production secrets
- Should recognize proper parameterized queries
- Should understand framework-specific security patterns

## Validation Process

1. **Run SAST scanner** on the entire `/sast-validation-suite` directory
2. **Compare findings** against this expected list
3. **Verify taint flow tracking** for complex multi-layer vulnerabilities
4. **Check false positive rate** by ensuring safe implementations are not flagged
5. **Validate CWE mapping** accuracy
6. **Test cross-file analysis** for vulnerabilities spanning multiple files

## Success Criteria

- **Detection Rate**: ≥90% of expected vulnerabilities found (68 total)
- **False Positive Rate**: ≤10% (safe implementations flagged)
- **Taint Tracking**: Complex 3+ layer flows correctly identified
- **Framework Awareness**: Next.js/React patterns properly handled
- **CWE Accuracy**: Correct vulnerability classification
- **NEW**: Cal.com Edge Case Detection: ≥85% of 16 framework-specific vulnerabilities
- **NEW**: Admin Bypass Detection: All 6 admin flag bypass patterns identified
- **NEW**: Organization Migration Flows: All 8 migration vulnerabilities detected

---

**Note**: This validation suite uses intentionally vulnerable patterns. Results should only be used to evaluate SAST tool capabilities in isolated test environments.