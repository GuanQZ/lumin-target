# Security Architecture Analysis Report

## Executive Summary

This application (Shannon Target) is a **vulnerable target application for security testing**. It contains **critical security vulnerabilities** intentionally built into the system. The application lacks proper authentication, authorization, session management, and security middleware - this is by design for security testing purposes.

---

## 1. Authentication Mechanisms Analysis

### 1.1 Login/Logout Logic

**File:** `src/main/java/com/example/shannontarget/controller/AuthController.java`

**Authentication Endpoints:**
| Endpoint | Method | Line | Description |
|----------|--------|------|-------------|
| `/login` | POST | 21-54 | Normal login with hardcoded credentials |
| `/dashboard` | GET | 57-69 | Protected dashboard endpoint |

**Critical Vulnerabilities Found:**

```java
// Lines 27-33: Authentication Bypass via HTTP Header
String adminHeader = request.getHeader("X-Admin-Header");
if (adminHeader != null) {
    response.setHeader("X-Auth-Status", "bypassed");
    return ResponseEntity.ok(Map.of(
        "success", true,
        "message", "Login bypassed via header",
        "user", "admin",
        "role", "administrator"
    ));
}
```

**Vulnerability:** Any request with `X-Admin-Header` header bypasses authentication completely.

```java
// Lines 35-47: Authentication Bypass via Cookie
Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie cookie : cookies) {
        if ("bypass_auth".equals(cookie.getName())) {
            response.setHeader("X-Auth-Status", "bypassed");
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Login bypassed via cookie",
                "user", "admin",
                "role", "administrator"
            ));
        }
    }
}
```

**Vulnerability:** Any request with `bypass_auth` cookie bypasses authentication.

**Hardcoded Credentials:**
```java
// Lines 16-17
private static final String VALID_USERNAME = "admin";
private static final String VALID_PASSWORD = "password123";
```

### 1.2 Token/JWT/Session - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

- No JWT token generation or validation
- No OAuth/OIDC implementation
- No MFA/2FA implementation
- No password encryption (plaintext comparison at line 49)

### 1.3 Complete Authentication Endpoints List

| Endpoint | Method | Path | Vulnerabilities |
|----------|--------|------|-----------------|
| `/login` | POST | `/login` | Auth bypass via header, auth bypass via cookie, hardcoded credentials, no rate limiting |
| `/dashboard` | GET | `/dashboard` | Broken access control, relies on spoofable header |

---

## 2. Authorization Mechanisms Analysis

### 2.1 RBAC/ABAC - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

- No Role-Based Access Control (RBAC)
- No Attribute-Based Access Control (ABAC)
- No `@PreAuthorize` or `@Secured` annotations
- No permission validation middleware

### 2.2 Authorization Code

**File:** `src/main/java/com/example/shannontarget/controller/AuthController.java`

```java
// Lines 57-69: Broken Access Control
@GetMapping("/dashboard")
public ResponseEntity<Map<String, Object>> dashboard(HttpServletRequest request) {
    String authStatus = request.getHeader("X-Auth-Status");
    if ("bypassed".equals(authStatus)) {
        return ResponseEntity.ok(Map.of(
            "message", "Welcome to admin dashboard",
            "data", "Sensitive information here"
        ));
    }
    return ResponseEntity.status(403).body(Map.of(
        "message", "Access denied"
    ));
}
```

**Vulnerability:** Access control relies on spoofable HTTP header - attacker can simply set `X-Auth-Status: bypassed`

---

## 3. Session Management Analysis

### 3.1 Session Storage - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

- No server-side session storage
- No session ID generation/validation
- No session timeout configuration

### 3.2 Cookie Configuration - FINDINGS

**Status:** ❌ NOT CONFIGURED

- No HttpOnly cookie flag
- No Secure cookie flag
- No SameSite cookie attribute
- No session cookie configuration in `application.properties`

**Application Properties:** `src/main/resources/application.properties`
```
server.port=8080
spring.application.name=shannon-target
```

No security-related configuration present.

### 3.3 Session Timeout - FINDINGS

**Status:** ❌ NOT CONFIGURED

No session timeout settings found.

---

## 4. Security Middleware Analysis

### 4.1 CSRF Protection - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

- No CSRF token validation
- No CSRF middleware
- No `@CsrfToken` annotations

### 4.2 CORS Configuration - FINDINGS

**Status:** ❌ NOT CONFIGURED

- No CORS configuration
- No allowed origins whitelist
- Default Spring Boot CORS policy (deny all)

### 4.3 Security Headers - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

- No security headers (X-Frame-Options, X-Content-Type-Options, etc.)
- No HTTPS enforcement
- No HSTS configuration

### 4.4 Input Validation - FINDINGS

**Status:** ❌ NOT IMPLEMENTED

**Vulnerable Endpoints:**

| Endpoint | Method | File | Line | Vulnerability Type |
|----------|--------|------|------|-------------------|
| `/fetch` | GET | ApiController.java | 17-31 | SSRF - No URL validation |
| `/user/search` | GET | ApiController.java | 36-68 | SQL Injection - String concatenation |
| `/user/lookup` | GET | ApiController.java | 70-100 | SQL Injection - String concatenation |
| `/comment` | POST | XssController.java | 21-31 | XSS - No output encoding |
| `/comment` | GET | XssController.java | 33-48 | XSS - No output encoding |
| `/search` | GET | XssController.java | 50-57 | XSS - No output encoding |
| `/profile` | POST | XssController.java | 59-69 | XSS - No output encoding |
| `/ping` | GET | CmdController.java | 21-50 | Command Injection |
| `/traceroute` | GET | CmdController.java | 52-79 | Command Injection |
| `/nslookup` | GET | CmdController.java | 81-108 | Command Injection |

---

## 5. Complete Security Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SHANNON TARGET APPLICATION                      │
│                     (Vulnerable Security Testing Target)               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     AUTHENTICATION (NONE)                       │   │
│  │  ┌──────────────────────────────────────────────────────────┐   │   │
│  │  │  POST /login                                               │   │   │
│  │  │  ├── Hardcoded credentials (admin/password123)            │   │   │
│  │  │  ├── BYPASS via X-Admin-Header header                     │   │   │
│  │  │  └── BYPASS via bypass_auth cookie                        │   │   │
│  │  └──────────────────────────────────────────────────────────┘   │   │
│  │  ┌──────────────────────────────────────────────────────────┐   │   │
│  │  │  GET /dashboard (Broken Access Control)                  │   │   │
│  │  │  └── Relies on X-Auth-Status header (spoofable)          │   │   │
│  │  └──────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    AUTHORIZATION (NONE)                        │   │
│  │  • No RBAC implementation                                       │   │
│  │  • No ABAC implementation                                        │   │
│  │  • No @PreAuthorize/@Secured annotations                       │   │
│  │  • No permission validation                                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  SESSION MANAGEMENT (NONE)                     │   │
│  │  • No session storage                                          │   │
│  │  • No cookie security (HttpOnly, Secure, SameSite)            │   │
│  │  • No session timeout                                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  SECURITY MIDDLEWARE (NONE)                    │   │
│  │  • No CSRF protection                                          │   │
│  │  • No CORS configuration                                        │   │
│  │  • No security headers                                         │   │
│  │  • No input validation                                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                         VULNERABLE ENDPOINTS                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  API CONTROLLER (ApiController.java)                                   │
│  ├── GET  /fetch          [SSRF]        Line 17-31                    │
│  ├── GET  /user/search    [SQLi]        Line 36-68                    │
│  └── GET  /user/lookup    [SQLi]        Line 70-100                   │
│                                                                         │
│  XSS CONTROLLER (XssController.java)                                   │
│  ├── POST /comment        [XSS]        Line 21-31                     │
│  ├── GET  /comment        [XSS]        Line 33-48                     │
│  ├── GET  /search         [XSS]        Line 50-57                      │
│  └── POST /profile        [XSS]        Line 59-69                     │
│                                                                         │
│  CMD CONTROLLER (CmdController.java)                                   │
│  ├── GET  /ping           [CMDi]       Line 21-50                     │
│  ├── GET  /traceroute     [CMDi]       Line 52-79                     │
│  └── GET  /nslookup       [CMDi]       Line 81-108                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Technology Stack

| Component | Technology | Version |
|-----------|------------|---------|
| Framework | Spring Boot | 3.2.0 |
| Template Engine | Thymeleaf | (bundled) |
| Database | H2 (in-memory) | runtime |
| Java | JDK | 17 |

---

## 7. SSO/OAuth/OIDC Implementation

**Status:** ❌ NOT IMPLEMENTED

No Single Sign-On, OAuth, or OpenID Connect implementation found.

---

## 8. Security Recommendations (For Reference)

Since this is a vulnerable testing target, these recommendations are for reference only:

1. **Authentication:**
   - Remove hardcoded credentials
   - Remove authentication bypass mechanisms
   - Implement proper password hashing (BCrypt)
   - Add rate limiting to prevent brute force
   - Implement proper session management

2. **Authorization:**
   - Implement RBAC with Spring Security
   - Add `@PreAuthorize` annotations
   - Validate permissions on all protected endpoints

3. **Session Management:**
   - Configure secure session cookies
   - Set appropriate session timeouts
   - Implement session fixation protection

4. **Security Middleware:**
   - Enable CSRF protection
   - Configure CORS properly
   - Add security headers
   - Implement input validation

5. **Vulnerability Fixes:**
   - Use parameterized queries for SQL
   - Implement output encoding for XSS
   - Validate URLs to prevent SSRF
   - Use whitelisting for command execution

---

## 9. Summary Table

| Security Category | Status | Severity |
|-------------------|--------|----------|
| Authentication | ❌ Missing | CRITICAL |
| Authorization | ❌ Missing | CRITICAL |
| Session Management | ❌ Missing | HIGH |
| CSRF Protection | ❌ Missing | HIGH |
| CORS Configuration | ❌ Missing | MEDIUM |
| Security Headers | ❌ Missing | MEDIUM |
| Input Validation | ❌ Missing | CRITICAL |
| SSRF Protection | ❌ Missing | CRITICAL |
| SQL Injection Protection | ❌ Missing | CRITICAL |
| XSS Protection | ❌ Missing | CRITICAL |
| Command Injection Protection | ❌ Missing | CRITICAL |

---

**Report Generated:** Security Pattern Hunter Analysis  
**Target:** Shannon Target Application (shannon-target)  
**Purpose:** Vulnerable application for security testing
