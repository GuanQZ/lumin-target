# Server-Side Request Influence Analysis

## Executive Summary
This analysis identifies all locations in the `/app/repos/lumin-20260317-000150-34` repository where user input could influence server-side requests. Focus is on network-accessible components including HTTP clients, URL fetchers, and command execution mechanisms.

---

## 1. HTTP Client / URL Fetcher (SSRF Vulnerability)

### Location: `src/main/java/com/example/shannontarget/controller/ApiController.java`

#### Endpoint: `GET /fetch`
- **Line 20-21**: Endpoint definition
```java
@GetMapping("/fetch")
public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url)
```

- **Line 24**: Direct URL usage without validation
```java
String response = restTemplate.getForObject(url, String.class);
```

- **Vulnerability**: User-controlled `url` parameter is passed directly to Spring's `RestTemplate` without any validation or sanitization.

- **Impact**: 
  - Can access internal services (e.g., `http://localhost:8080/admin`)
  - Can access cloud metadata endpoints (e.g., `http://169.254.169.254/latest/meta-data/`)
  - Can perform port scanning of internal network
  - Can access internal databases or services

- **Code Location**: Lines 20-35

---

## 2. Command Execution (OS Command Injection)

### Location: `src/main/java/com/example/shannontarget/controller/CmdController.java`

#### Endpoint: `GET /ping`
- **Line 17-18**: Endpoint definition
```java
@GetMapping("/ping")
public ResponseEntity<Map<String, Object>> ping(@RequestParam(defaultValue = "127.0.0.1") String host)
```

- **Line 24**: Command construction with user input
```java
String command = "ping -n 2 " + host;
```

- **Line 26**: Process execution
```java
ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
```

- **Code Location**: Lines 17-46
- **Attack Vector**: `?host=127.0.0.1; whoami`

---

#### Endpoint: `GET /traceroute`
- **Line 56-57**: Endpoint definition
```java
@GetMapping("/traceroute")
public ResponseEntity<Map<String, Object>> traceroute(@RequestParam String target)
```

- **Line 60**: Command construction with user input
```java
String command = "tracert -d -w 100 " + target;
```

- **Line 62**: Process execution
```java
ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
```

- **Code Location**: Lines 56-85

---

#### Endpoint: `GET /nslookup`
- **Line 93-94**: Endpoint definition
```java
@GetMapping("/nslookup")
public ResponseEntity<Map<String, Object>> nslookup(@RequestParam String domain)
```

- **Line 97**: Command construction with user input
```java
String command = "nslookup " + domain;
```

- **Line 99**: Process execution
```java
ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
```

- **Code Location**: Lines 93-122

---

## 3. SQL Injection (Data Retrieval with User Input)

### Location: `src/main/java/com/example/shannontarget/controller/ApiController.java`

#### Endpoint: `GET /user/search`
- **Line 42-43**: Endpoint definition
```java
@GetMapping("/user/search")
public ResponseEntity<Map<String, Object>> searchUser(@RequestParam String username)
```

- **Line 56**: SQL query with direct string concatenation
```java
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
```

- **Line 58**: Query execution
```java
ResultSet rs = queryStmt.executeQuery(sql);
```

- **Code Location**: Lines 42-72

---

#### Endpoint: `GET /user/lookup`
- **Line 87-88**: Endpoint definition
```java
@GetMapping("/user/lookup")
public ResponseEntity<Map<String, Object>> lookupUser(@RequestParam(defaultValue = "1") String id)
```

- **Line 100**: SQL query with direct string concatenation
```java
String sql = "SELECT * FROM users WHERE id = " + id;
```

- **Line 102**: Query execution
```java
ResultSet rs = queryStmt.executeQuery(sql);
```

- **Code Location**: Lines 87-120

---

## Summary Table

| Component | Endpoint | Parameter | File | Lines | Risk |
|-----------|----------|-----------|------|-------|------|
| HTTP Client (RestTemplate) | `/fetch` | `url` | ApiController.java | 20-35 | **CRITICAL - SSRF** |
| Command Execution | `/ping` | `host` | CmdController.java | 17-46 | **CRITICAL - OS Command Injection** |
| Command Execution | `/traceroute` | `target` | CmdController.java | 56-85 | **CRITICAL - OS Command Injection** |
| Command Execution | `/nslookup` | `domain` | CmdController.java | 93-122 | **CRITICAL - OS Command Injection** |
| SQL Query | `/user/search` | `username` | ApiController.java | 42-72 | **HIGH - SQL Injection** |
| SQL Query | `/user/lookup` | `id` | ApiController.java | 87-120 | **HIGH - SQL Injection** |

---

## Components NOT Found

- **Webhook Handlers**: No webhook implementations found
- **External API Integrations**: No external API integrations (besides the SSRF /fetch endpoint)
- **File Inclusion Mechanisms**: No file inclusion (include, require, etc.)
- **Template Injection**: No server-side template engines used
- **XML External Entity (XXE)**: No XML parsing endpoints

---

## Network-Accessible Entry Points Summary

The following HTTP endpoints accept user input and can influence server-side requests:

1. **`GET /fetch?url=<user-controlled>`** - Full URL control for server-side requests
2. **`GET /ping?host=<user-controlled>`** - Command injection, can execute arbitrary OS commands
3. **`GET /traceroute?target=<user-controlled>`** - Command injection
4. **`GET /nslookup?domain=<user-controlled>`** - Command injection
5. **`GET /user/search?username=<user-controlled>`** - SQL injection
6. **`GET /user/lookup?id=<user-controlled>`** - SQL injection

---

## Security Impact Assessment

The most critical vulnerabilities from a network perspective are:

1. **SSRF via /fetch endpoint** - Allows attacker to make the server request arbitrary URLs
2. **Command Injection via /ping, /traceroute, /nslookup** - Allows arbitrary command execution which can be used for lateral movement, network scanning, etc.

Both categories can be exploited to:
- Scan internal networks
- Access internal services
- Exfiltrate data
- Perform attacks on other systems
