# Security Architecture Analysis - Complete Mapping

## Executive Summary

This analysis maps the complete security architecture of the `lumin-20260317-000150-34` codebase (Shannon Target application). The application is a **Spring Boot 3.2.0** vulnerable target application for security testing with **multiple critical security vulnerabilities**.

---

## 1. Authentication Flows

### 1.1 Login Endpoint

| Attribute | Details |
|-----------|---------|
| **File** | `src/main/java/com/example/shannontarget/controller/AuthController.java` |
| **Lines** | 23-65 |
| **Endpoint** | `POST /login` |
| **Method** | `@PostMapping("/login")` |

**Authentication Mechanism:** Basic username/password validation with hardcoded credentials.

```java
// Lines 24-25
private static final String VALID_USERNAME = "admin";
private static final String VALID_PASSWORD = "password123";
```

**Vulnerabilities Identified:**

| Line | Vulnerability | Description |
|------|---------------|-------------|
| 30-38 | **Authentication Bypass via Header** | If `X-Admin-Header` is present with ANY value, authentication is bypassed |
| 42-52 | **Authentication Bypass via Cookie** | If cookie `bypass_auth` is present, authentication is bypassed |
| 59-64 | **No Rate Limiting** | Vulnerable to brute force attacks |

### 1.2 Authentication Bypass Mechanisms

**Header-Based Bypass:**
- **File:** `src/main/java/com/example/shannontarget/controller/AuthController.java`
- **Lines:** 30-38
- **Header:** `X-Admin-Header` (any value)

```java
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

**Cookie-Based Bypass:**
- **File:** `src/main/java/com/example/shannontarget/controller/AuthController.java`
- **Lines:** 42-52
- **Cookie:** `bypass_auth`

```java
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

### 1.3 Protected Dashboard Endpoint

| Attribute | Details |
|-----------|---------|
| **File** | `src/main/java/com/example/shannontarget/controller/AuthController.java` |
| **Lines** | 70-87 |
| **Endpoint** | `GET /dashboard` |
| **Method** | `@GetMapping("/dashboard")` |

```java
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

**Vulnerability:** Dashboard access is controlled solely by the `X-Auth-Status` header, which can be trivially spoofed.

---

## 2. Authorization Mechanisms

### 2.1 Role-Based Access Control (RBAC)

**Status:** NOT IMPLEMENTED

The application has **NO RBAC implementation**. Role assignments are hardcoded in responses:

| File | Line | Role Returned |
|------|------|---------------|
| `AuthController.java` | 37 | `"administrator"` (via header bypass) |
| `AuthController.java` | 51 | `"administrator"` (via cookie bypass) |
| `AuthController.java` | 63 | `"user"` (normal login) |

### 2.2 Permission Validators

**Status:** NOT IMPLEMENTED

No permission validators, `@PreAuthorize`, `@Secured`, or method-level security annotations exist.

### 2.3 Authorization Header Handling

| File | Line | Purpose |
|------|------|---------|
| `AuthController.java` | 32 | Sets `X-Auth-Status: bypassed` |
| `AuthController.java` | 46 | Sets `X-Auth-Status: bypassed` |
| `AuthController.java` | 78 | Reads `X-Auth-Status` header |

---

## 3. Session Management

### 3.1 Session Handling

**Status:** NOT IMPLEMENTED

- No HTTP session management (`HttpSession` not used)
- No session fixation protection
- No session timeout configuration
- No concurrent session control

### 3.2 Cookie Security

**File:** `src/main/java/com/example/shannontarget/controller/AuthController.java`

| Line | Issue |
|------|-------|
| 42 | Reads cookies without validation |
| 44-45 | Iterates all cookies looking for `bypass_auth` |

**No cookie security attributes:**
- No `Secure` flag
- No `HttpOnly` flag
- No `SameSite` attribute
- No `Secure` cookie prefix

---

## 4. JWT Handling

**Status:** NOT IMPLEMENTED

No JWT token generation, validation, or handling found in the codebase.

---

## 5. OAuth Flows

**Status:** NOT IMPLEMENTED

No OAuth 2.0, OpenID Connect, or social login implementations.

---

## 6. Security Middleware

### 6.1 Spring Security Configuration

**Status:** NOT PRESENT

- No `WebSecurityConfig` class
- No `@EnableWebSecurity` annotation
- No `SecurityFilterChain` bean
- No custom `SecurityFilter` implementations

**File:** `src/main/java/com/example/shannontarget/ShannonTargetApplication.java`

```java
// Lines 1-10
package com.example.shannontarget;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ShannonTargetApplication {
    public static void main(String[] args) {
        SpringApplication.run(ShannonTargetApplication.class, args);
    }
}
```

### 6.2 Request Interceptors

**Status:** NOT PRESENT

No custom interceptors or filters.

### 6.3 Method-Level Security

**Status:** NOT PRESENT

No `@Secured`, `@RolesAllowed`, or `@PreAuthorize` annotations.

---

## 7. Security Headers Configuration

### 7.1 HTTP Security Headers

**Status:** NOT CONFIGURED

No security headers are set programmatically. The application does NOT implement:

| Header | Status |
|--------|--------|
| `X-Content-Type-Options` | ❌ Not set |
| `X-Frame-Options` | ❌ Not set |
| `X-XSS-Protection` | ❌ Not set |
| `Strict-Transport-Security` | ❌ Not set |
| `Content-Security-Policy` | ❌ Not set |
| `Referrer-Policy` | ❌ Not set |
| `Permissions-Policy` | ❌ Not set |

### 7.2 CORS Configuration

**Status:** NOT CONFIGURED

No CORS configuration - default deny all.

### 7.3 Response Headers Set by Application

| Header | Value | Location |
|--------|-------|----------|
| `X-Auth-Status` | `bypassed` | `AuthController.java:32, 46` |

---

## 8. Vulnerability Summary by Endpoint

### 8.1 Authentication Endpoints

| Endpoint | File | Lines | Vulnerabilities |
|----------|------|-------|-----------------|
| `POST /login` | `AuthController.java` | 23-65 | Authentication Bypass (Header), Authentication Bypass (Cookie), Hardcoded Credentials, No Rate Limiting |
| `GET /dashboard` | `AuthController.java` | 70-87 | Authorization Bypass via Header Spoofing |

### 8.2 API Endpoints

| Endpoint | File | Lines | Vulnerabilities |
|----------|------|-------|-----------------|
| `GET /fetch` | `ApiController.java` | 19-35 | **SSRF** - No URL validation |
| `GET /user/search` | `ApiController.java` | 40-75 | **SQL Injection** - Direct string concatenation |
| `GET /user/lookup` | `ApiController.java` | 77-119 | **SQL Injection** - Direct string concatenation |

### 8.3 XSS Endpoints

| Endpoint | File | Lines | Vulnerabilities |
|----------|------|-------|-----------------|
| `POST /comment` | `XssController.java` | 21-31 | **XSS** - No input sanitization |
| `GET /comment` | `XssController.java` | 33-49 | **XSS** - No output encoding |
| `GET /search` | `XssController.java` | 51-59 | **XSS** - No output encoding |
| `POST /profile` | `XssController.java` | 61-72 | **XSS** - No input validation |

### 8.4 Command Injection Endpoints

| Endpoint | File | Lines | Vulnerabilities |
|----------|------|-------|-----------------|
| `GET /ping` | `CmdController.java` | 15-41 | **Command Injection** - Direct string concatenation |
| `GET /traceroute` | `CmdController.java` | 43-69 | **Command Injection** - Direct string concatenation |
| `GET /nslookup` | `CmdController.java` | 71-97 | **Command Injection** - Direct string concatenation |

---

## 9. Complete File Location Map

### 9.1 Java Source Files

```
src/main/java/com/example/shannontarget/
├── ShannonTargetApplication.java          (Lines: 1-10)
│   └── Main Spring Boot application - NO security configuration
│
├── controller/
│   ├── AuthController.java                (Lines: 1-87)
│   │   ├── Login endpoint                 (Lines: 23-65)
│   │   │   ├── Hardcoded credentials       (Lines: 24-25)
│   │   │   ├── Header bypass                (Lines: 30-38)
│   │   │   └── Cookie bypass                (Lines: 42-52)
│   │   └── Dashboard endpoint               (Lines: 70-87)
│   │
│   ├── ApiController.java                  (Lines: 1-120)
│   │   ├── SSRF endpoint                   (Lines: 18-35)
│   │   ├── SQL Injection search            (Lines: 40-75)
│   │   └── SQL Injection lookup            (Lines: 77-119)
│   │
│   ├── XssController.java                   (Lines: 1-72)
│   │   ├── Comment POST                     (Lines: 21-31)
│   │   ├── Comment GET                      (Lines: 33-49)
│   │   ├── Search                           (Lines: 51-59)
│   │   └── Profile                          (Lines: 61-72)
│   │
│   └── CmdController.java                    (Lines: 1-97)
│       ├── Ping                             (Lines: 15-41)
│       ├── Traceroute                       (Lines: 43-69)
│       └── Nslookup                         (Lines: 71-97)
```

### 9.2 Configuration Files

```
src/main/resources/
├── application.properties                   (Lines: 1-2)
│   └── No security configuration
│
└── static/
    └── index.html                           (Lines: 1-625)
        ├── Login form                       (Lines: 200-230)
        │   └── Bypass checkbox              (Lines: 206-208)
        └── Frontend JavaScript              (Lines: 300-625)
            └── X-Admin-Header injection     (Line: 391)
```

### 9.3 Build Configuration

```
pom.xml                                      (Lines: 1-45)
├── Spring Boot Starter Web                  (Lines: 18-20)
├── Spring Boot Thymeleaf                    (Lines: 21-23)
└── H2 Database                               (Lines: 24-27)
    └── Runtime only - vulnerable SQL
```

---

## 10. Security Components Status

| Component | Status | Location |
|-----------|--------|----------|
| Spring Security | ❌ NOT PRESENT | N/A |
| JWT Implementation | ❌ NOT PRESENT | N/A |
| OAuth 2.0 | ❌ NOT PRESENT | N/A |
| RBAC | ❌ NOT PRESENT | N/A |
| Permission Validators | ❌ NOT PRESENT | N/A |
| Security Headers | ❌ NOT CONFIGURED | N/A |
| Rate Limiting | ❌ NOT PRESENT | N/A |
| Input Validation | ❌ NOT PRESENT | N/A |
| CSRF Protection | ❌ NOT PRESENT | N/A |
| XSS Protection | ❌ NOT PRESENT | N/A |
| SQL Injection Prevention | ❌ NOT PRESENT | N/A |
| SSRF Protection | ❌ NOT PRESENT | N/A |
| Command Injection Prevention | ❌ NOT PRESENT | N/A |

---

## 11. Attack Surface Summary

### Critical Vulnerabilities

| # | Vulnerability | Severity | File | Lines |
|---|---------------|----------|------|-------|
| 1 | Authentication Bypass (Header) | **CRITICAL** | `AuthController.java` | 30-38 |
| 2 | Authentication Bypass (Cookie) | **CRITICAL** | `AuthController.java` | 42-52 |
| 3 | SQL Injection (search) | **CRITICAL** | `ApiController.java` | 68 |
| 4 | SQL Injection (lookup) | **CRITICAL** | `ApiController.java` | 106 |
| 5 | SSRF | **CRITICAL** | `ApiController.java` | 27 |
| 6 | Command Injection (ping) | **CRITICAL** | `CmdController.java` | 28 |
| 7 | Command Injection (traceroute) | **CRITICAL** | `CmdController.java` | 55 |
| 8 | Command Injection (nslookup) | **CRITICAL** | `CmdController.java` | 82 |
| 9 | XSS (multiple endpoints) | **HIGH** | `XssController.java` | 21-72 |
| 10 | Hardcoded Credentials | **HIGH** | `AuthController.java` | 24-25 |

---

## 12. Dependencies Analysis

### pom.xml - Security-Relevant Dependencies

| Dependency | Version | Status |
|------------|---------|--------|
| spring-boot-starter-web | 3.2.0 | ✅ Present (but not secured) |
| spring-boot-starter-thymeleaf | 3.2.0 | ✅ Present |
| h2 database | (managed) | ✅ Present (vulnerable) |
| spring-boot-starter-security | ❌ | **MISSING** |
| spring-boot-starter-oauth2-client | ❌ | **MISSING** |
| jjwt | ❌ | **MISSING** |

---

## Conclusion

The `lumin-20260317-000150-34` codebase is a **purpose-built vulnerable application** designed for security testing. It contains **NO security controls** for:

1. **Authentication** - Multiple trivial bypass mechanisms
2. **Authorization** - No RBAC or permission system
3. **Session Management** - No session handling
4. **JWT/OAuth** - Not implemented
5. **Security Headers** - Not configured
6. **Input Validation** - No validation on any endpoint
7. **Secure Coding** - Intentionally vulnerable to OWASP Top 10

This is **NOT** a production-ready application and should only be used in isolated testing environments.
