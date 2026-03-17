# Penetration Test Scope & Boundaries

**Primary Directive:** Your analysis is strictly limited to the **network-accessible attack surface** of the application. All subsequent tasks must adhere to this scope. Before reporting any finding (e.g., an entry point, a vulnerability sink), you must first verify it meets the "In-Scope" criteria.

### In-Scope: Network-Reachable Components
A component is considered **in-scope** if its execution can be initiated, directly or indirectly, by a network request that the deployed application server is capable of receiving. This includes:
- Publicly exposed web pages and API endpoints.
- Endpoints requiring authentication via the application's standard login mechanisms.
- Any developer utility, debug console, or script that has been mistakenly exposed through a route or is otherwise callable from other in-scope, network-reachable code.

### Out-of-Scope: Locally Executable Only
A component is **out-of-scope** if it **cannot** be invoked through the running application's network interface and requires an execution context completely external to the application's request-response cycle. This includes tools that must be run via:
- A command-line interface (e.g., `go run ./cmd/...`, `python scripts/...`).
- A development environment's internal tooling (e.g., a "run script" button in an IDE).
- CI/CD pipeline scripts or build tools (e.g., Dagger build definitions).
- Database migration scripts, backup tools, or maintenance utilities.
- Local development servers, test harnesses, or debugging utilities.
- Static files or scripts that require manual opening in a browser (not served by the application).

---

## 1. Executive Summary

**目标应用概述:** 这是一个专为安全测试设计的Spring Boot 3.2.0目标应用程序(shannon-target)，运行在8080端口，包含多个故意植入的安全漏洞，用于渗透测试训练和研究。

**关键发现:**
- **严重漏洞密集**: 发现5类共10+个严重安全漏洞，包括认证绕过、SQL注入、命令注入、SSRF和XSS
- **认证机制形同虚设**: 登录端点存在双重认证绕过机制(Header和Cookie)，可获取管理员权限
- **缺乏输入验证**: 所有用户输入端点均未实施任何形式的输入验证或输出编码
- **数据库直接暴露**: 使用H2内存数据库，存在SQL注入风险，数据持久性受限但攻击面完整

**攻击面评估:** 该应用完全暴露在公网环境下，所有REST控制器端点均无需认证即可访问(除dashboard需简单绕过)，是理想的渗透测试目标。攻击者可通过组合漏洞实现从信息收集到服务器完全接管的全链条攻击。

---

## 2. Architecture & Technology Stack

### Framework & Language
- **框架**: Spring Boot 3.2.0 (基于Spring Framework 6.x)
- **语言**: Java 17
- **Web框架**: Spring MVC (REST控制器)
- **模板引擎**: Thymeleaf (已集成但未在当前路由中充分利用)
- **数据库**: H2内存数据库 (jdbc:h2:mem:testdb)
- **构建工具**: Maven 3.x
- **打包方式**: JAR (可执行Spring Boot应用)

### Architectural Pattern
- **模式**: 单体Spring Boot REST API应用
- **架构风格**: 分层架构 (Controller → 业务逻辑内联 → 数据层直连)
- **部署模式**: 容器化 (Dockerfile存在)
- **会话管理**: 无状态REST + Servlet Cookie (存在安全隐患)

### Critical Security Components
- **认证层**: 自定义表单认证 (AuthController) - 存在严重设计缺陷
- **授权层**: 无基于角色的访问控制(RBAC)实现
- **输入处理**: 无全局输入验证过滤器
- **输出编码**: 无全局XSS防护
- **SQL处理**: 原始JDBC直连查询 + 字符串拼接

---

## 3. Authentication & Authorization Deep Dive

### Authentication Mechanisms
该应用实现了一个存在严重设计缺陷的简单表单认证系统。

**认证端点清单:**
| 端点 | 方法 | 文件位置 | 安全问题 |
|------|------|----------|----------|
| `/login` | POST | AuthController.java:24 | 认证绕过漏洞 |
| `/dashboard` | GET | AuthController.java:62 | 权限绕过漏洞 |

**认证绕过机制分析:**

1. **Header绕过** (AuthController.java:29-37):
```java
String adminHeader = request.getHeader("X-Admin-Header");
if (adminHeader != null) {
    // 直接返回管理员权限，无需任何凭证
    return ResponseEntity.ok(Map.of(
        "success", true,
        "message", "Login bypassed via header",
        "user", "admin",
        "role", "administrator"
    ));
}
```
此漏洞允许任何携带任意值X-Admin-Header的请求绕过认证。

2. **Cookie绕过** (AuthController.java:39-50):
```java
Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie cookie : cookies) {
        if ("bypass_auth".equals(cookie.getName())) {
            // Cookie存在即绕过认证
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
此漏洞允许任何设置bypass_auth cookie的请求绕过认证。

3. **硬编码凭证** (AuthController.java:17-18):
```java
private static final String VALID_USERNAME = "admin";
private static final String VALID_PASSWORD = "password123";
```
静态凭证且无密码策略 enforced。

**SSO/OAuth/OIDC Flows:** 不适用 - 本应用未实现任何第三方身份验证集成。

### Session Management
- **会话存储**: 无服务器端会话存储，使用无状态REST
- **Cookie配置**: 未设置任何安全标志 (HttpOnly, Secure, SameSite)
- **会话标识**: 未实现自定义会话令牌机制

**关键代码位置:** Cookie处理在AuthController.java:39-50，未配置任何安全属性。

### Authorization Model
- **模型**: 极简基于角色模型 (硬编码"administrator"和"user"角色)
- **实现**: 无Spring Security依赖，仅在dashboard端点做简单字符串检查
- **权限检查绕过**: dashboard端点通过检查X-Auth-Status header判断，但该header可由客户端任意设置

---

## 4. Data Security & Storage

### Database Security
- **数据库类型**: H2内存数据库 (jdbc:h2:mem:testdb)
- **连接凭证**: 硬编码用户名"sa"，空密码 (ApiController.java:30-32)
- **查询方式**: 原始JDBC Statement (非PreparedStatement)
- **SQL注入风险**: 极高 - 所有查询使用字符串拼接

**数据库连接代码位置:**
- ApiController.java:28-35 (searchUser方法)
- ApiController.java:64-71 (lookupUser方法)

### Data Flow Security
- **用户输入**: 直接从@RequestParam获取，未经过滤
- **SQL查询**: 字符串拼接直接执行
- **响应输出**: 原始JSON响应，无数据脱敏
- **敏感数据**: 用户名、邮箱、角色信息以明文传输和存储

### Multi-tenant Data Isolation
- **多租户**: 不适用 - 单租户应用
- **数据隔离**: 所有用户共享同一H2内存数据库实例

---

## 5. Attack Surface Analysis

### External Entry Points

| 端点 | 方法 | 功能 | 漏洞类型 | 风险等级 |
|------|------|------|----------|----------|
| `/login` | POST | 用户登录 | 认证绕过 | **严重** |
| `/dashboard` | GET | 管理仪表板 | 权限绕过 | **严重** |
| `/fetch` | GET | URL内容获取 | SSRF | **严重** |
| `/user/search` | GET | 用户搜索 | SQL注入 | **严重** |
| `/user/lookup` | GET | 用户查询 | SQL注入 | **严重** |
| `/ping` | GET | ping命令执行 | 命令注入 | **严重** |
| `/traceroute` | GET | traceroute执行 | 命令注入 | **严重** |
| `/nslookup` | GET | DNS查询执行 | 命令注入 | **严重** |
| `/comment` | POST/GET | 评论功能 | XSS | **高** |
| `/search` | GET | 搜索功能 | XSS | **高** |
| `/profile` | POST | 用户资料更新 | XSS | **高** |

### Input Validation Patterns
- **现状**: 完全无输入验证
- **参数获取**: 使用Spring @RequestParam直接映射
- **过滤机制**: 无
- **编码处理**: 无

### Background Processing
- **异步处理**: 不适用 - 所有请求同步处理
- **定时任务**: 无
- **消息队列**: 无

### Internal Service Communication
- **服务间通信**: 仅RestTemplate用于/fetch端点的外部HTTP请求
- **信任边界**: 无内部网络隔离，任何URL均可访问

---

## 6. Infrastructure & Operational Security

### Secrets Management
- **硬编码凭证**: VALID_USERNAME = "admin", VALID_PASSWORD = "password123"
- **数据库凭证**: sa/空密码
- **密钥存储**: 无 - 所有凭据明文存储在源代码中

### Configuration Security
- **配置文件**: application.properties
- **运行端口**: 8080 (server.port=8080)
- **安全头**: 未配置任何HTTP安全头
- **CORS**: 未配置
- **SSL/TLS**: 未启用

### External Dependencies
- **Spring Boot Starter Web**: 3.2.0
- **Spring Boot Starter Thymeleaf**: 3.2.0
- **H2 Database**: 运行时依赖

### Monitoring & Logging
- **日志框架**: Spring Boot默认日志 (SLF4J)
- **安全日志**: 无专门安全审计日志
- **请求日志**: 未配置访问日志

---

## 7. Overall Codebase Indexing

**目录结构:**
```
shannon-target/
├── pom.xml                          # Maven构建配置
├── Dockerfile                       # Docker容器配置
├── .github/workflows/docker.yml     # CI/CD配置
└── src/main/
    ├── java/com/example/shannontarget/
    │   ├── ShannonTargetApplication.java    # Spring Boot主类
    │   └── controller/
    │       ├── ApiController.java           # API端点(SQL注入, SSRF)
    │       ├── AuthController.java          # 认证端点(认证绕过)
    │       ├── CmdController.java           # 系统命令端点(命令注入)
    │       └── XssController.java           # XSS漏洞端点
    └── resources/
        ├── application.properties           # 应用配置
        └── static/
            └── index.html                   # 静态首页
```

**代码组织:** 该应用采用标准Spring Boot项目结构，所有安全相关逻辑集中在controller包下的4个REST控制器中。每个控制器对应一类特定漏洞，便于安全测试和教学演示。

**无安全框架:** 值得注意的是，该应用未使用Spring Security框架，所有认证授权逻辑均为自定义实现，存在多处严重设计缺陷。

---

## 8. Critical File Paths

### Configuration
- `pom.xml` - Maven依赖和构建配置
- `Dockerfile` - Docker镜像定义
- `src/main/resources/application.properties` - 应用运行时配置

### Authentication & Authorization
- `src/main/java/com/example/shannontarget/controller/AuthController.java` - 所有认证逻辑
  - Line 17-18: 硬编码凭证定义
  - Line 24-37: Header认证绕过漏洞
  - Line 39-50: Cookie认证绕过漏洞
  - Line 62-73: Dashboard权限检查(可绕过)

### API & Routing
- `src/main/java/com/example/shannontarget/controller/ApiController.java` - API端点
  - Line 21-35: /fetch SSRF漏洞端点
  - Line 45-82: /user/search SQL注入端点
  - Line 86-112: /user/lookup SQL注入端点
  
- `src/main/java/com/example/shannontarget/controller/CmdController.java` - 命令注入端点
  - Line 20-48: /ping命令注入
  - Line 53-74: /traceroute命令注入
  - Line 79-100: /nslookup命令注入

- `src/main/java/com/example/shannontarget/controller/XssController.java` - XSS端点
  - Line 19-30: /comment POST XSS
  - Line 35-50: /comment GET XSS
  - Line 55-64: /search XSS
  - Line 69-79: /profile XSS

### Data Models & DB Interaction
- H2内存数据库连接: ApiController.java:28-35, 64-71

### Dependency Manifests
- `pom.xml` - 包含所有Maven依赖

### Sensitive Data & Secrets Handling
- 硬编码凭证: AuthController.java:17-18

### Middleware & Input Validation
- 无 - 应用中不存在任何输入验证中间件

### Logging & Monitoring
- Spring Boot默认日志配置 (无自定义安全日志)

---

## 9. XSS Sinks and Render Contexts

### XSS Sink Details

**1. /comment POST端点 (XssController.java:19-30)**
- **Sink Type**: 输入存储 + 反射输出
- **Context**: JSON响应体
- **漏洞描述**: 用户提交的评论内容直接存储和返回，无任何HTML编码
- **Payload示例**: `<script>alert(1)</script>`

**2. /comment GET端点 (XssController.java:35-50)**
- **Sink Type**: 反射型XSS
- **Context**: JSON响应体 (filter参数)
- **漏洞描述**: filter查询参数直接反映在响应中
- **Payload示例**: `?filter=<img src=x onerror=alert(1)>`

**3. /search端点 (XssController.java:55-64)**
- **Sink Type**: 反射型XSS
- **Context**: JSON响应 (query参数)
- **漏洞描述**: 搜索查询参数直接返回
- **Payload示例**: `?q=<script>alert(document.cookie)</script>`

**4. /profile端点 (XssController.java:69-79)**
- **Sink Type**: 存储型XSS
- **Context**: JSON响应 (name和bio参数)
- **漏洞描述**: 用户资料字段无任何过滤
- **Payload示例**: POST data: name=<script>alert(1)</script>&bio=<img onerror=alert(1) src=x>

### 攻击场景
攻击者可结合存储型XSS和认证绕过漏洞，以管理员身份注入持久化XSS payload，当其他用户访问受影响页面时触发。

---

## 10. SSRF Sinks

### SSRF Sink Details

**1. /fetch端点 (ApiController.java:21-35)**
- **Sink Type**: 用户控制URL的服务器端请求
- **HTTP Client**: Spring RestTemplate
- **漏洞描述**: url参数直接用于HTTP请求，无任何验证
- **攻击向量**:
  - 内部服务访问: `?url=http://localhost:8080/dashboard`
  - 云元数据: `?url=http://169.254.169.254/latest/meta-data/`
  - 内部端口扫描: `?url=http://192.168.1.1:22`
  - 敏感文件: `?url=file:///etc/passwd` (取决于RestTemplate配置)

**影响范围:**
- 可探测内网服务
- 可获取云环境元数据(如果在云环境运行)
- 可绕过防火墙访问受限内部服务

---

## Conclusion

**整体安全评估:** 该目标应用存在严重安全缺陷，不应在生产环境部署。所有用户输入端点均未实施基本的安全控制，攻击者可轻易实现:
1. 认证绕过获取管理员权限
2. 通过SQL注入提取数据库数据
3. 通过命令注入执行任意系统命令
4. 通过SSRF探测和攻击内部基础设施
5. 通过XSS窃取用户会话和敏感信息

**测试建议:**
- 优先测试认证绕过漏洞组合(Simple Auth Bypass)
- 命令注入可实现服务器完全接管
- SSRF在云环境部署时风险极高

---

*Report Generated: Security Assessment Code Analysis*
*Target: shannon-target v1.0.0*
*Framework: Spring Boot 3.2.0*
