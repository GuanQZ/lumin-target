# 渗透测试范围与边界

**主要指令：** 您的分析严格限于应用程序的**网络可访问攻击面**。所有后续任务必须遵守此范围。在报告任何发现之前（例如入口点、漏洞接收器），必须首先验证它是否符合"在范围内"标准。

### 范围内：网络可访问组件
如果组件的执行可以由部署的应用程序服务器直接或间接接收的网络请求发起，则该组件被视为**在范围内**。这包括：
- 公开暴露的网页和API端点。
- 需要通过应用程序标准登录机制进行身份验证的端点。
- 任何通过路由错误暴露的开发者工具、调试控制台或脚本，或者可以通过其他在范围内的网络可访问代码间接调用的脚本。

### 范围外：仅本地可执行
如果组件**无法**通过运行中的应用程序的网络接口调用，并且需要完全在应用程序请求-响应周期之外的执行上下文，则该组件**在范围外**。这包括必须通过以下方式运行的工具：
- 命令行界面（例如 `go run ./cmd/...`、`python scripts/...`）。
- 开发环境的内部工具（例如IDE中的"运行脚本"按钮）。
- CI/CD管道脚本或构建工具（例如Dagger构建定义）。
- 数据库迁移脚本、备份工具或维护实用程序。
- 本地开发服务器、测试工具或调试实用程序。
- 需要手动在浏览器中打开的静态文件或脚本（不是由应用程序提供）。

---

## 1. 执行摘要

**Shannon Target** 是一个基于 Spring Boot 3.2.0 和 Java 17 构建的易受攻击的演示应用程序，专门用于安全测试。该应用程序暴露了多个严重的网络安全漏洞，使其成为渗透测试练习的理想目标，但同时也极易受到真实攻击。

应用程序存在**关键级别**的认证绕过漏洞，允许攻击者通过简单的HTTP头或Cookie绕过身份验证获取管理员权限。此外，还存在**高危级别**的注入漏洞，包括命令注入、SQL注入、SSRF和XSS，所有这些都直接暴露在网络可访问的端点上。应用程序的前端是一个单页应用程序(SPA)，通过JavaScript与这些易受攻击的后端端点交互，提供了一个完整的攻击链视图。

由于缺乏速率限制、输入验证和输出编码，攻击者可以轻松地进行暴力破解、脚本注入和内部服务探测。该应用程序没有使用任何安全头部（如HSTS、CSP）或加密机制来保护数据。

---

## 2. 架构与技术栈

### 框架与语言
- **框架：** Spring Boot 3.2.0
- **语言：** Java 17
- **构建工具：** Maven 3.9
- **前端框架：** 原生HTML/CSS/JavaScript (单页应用)
- **模板引擎：** Thymeleaf (已配置但未使用)
- **数据库：** H2 内存数据库

**安全影响分析：** Spring Boot 3.2.0 是最新版本，带来了现代安全特性，但该应用程序完全没有利用这些特性。Java 17 提供了良好的内存管理和加密API，但应用程序存在明显的安全缺陷。H2 内存数据库的使用意味着数据不会持久化，但在运行时仍可能被SQL注入攻击提取。

### 架构模式
- **模式：** RESTful API + 前端SPA混合架构
- **结构：** 标准Spring MVC项目结构
  - `controller/` - 所有REST端点
  - `resources/static/` - 静态前端文件
  - `resources/application.properties` - 应用配置

**安全影响分析：** 应用程序采用简单的单体架构，所有端点都集中在一个控制器包中。这使得攻击面变得清晰，但也意味着一旦攻击者获得访问权限，他们可以访问所有功能。缺少任何安全中间件或Web应用防火墙(WAF)配置。

### 关键安全组件
- **认证：** 硬编码凭证 + HTTP头绕过机制
- **授权：** 基于请求头的简单检查
- **数据存储：** H2内存数据库（无加密）
- **网络工具：** ProcessBuilder直接执行系统命令

**安全影响分析：** 应用程序没有任何真正的安全组件。认证机制存在致命缺陷，允许通过HTTP头完全绕过。授权检查仅依赖一个可伪造的请求头。数据库连接使用明文凭据，没有任何加密。网络工具通过字符串拼接执行命令，存在严重的命令注入风险。

---

## 3. 身份验证与授权深度分析

### 认证机制
该应用程序实现了三种认证机制，但都存在严重的安全缺陷：

#### 3.1 正常登录端点
**文件位置：** `src/main/java/com/example/shannontarget/controller/AuthController.java`

```java
@PostMapping("/login")
public ResponseEntity<Map<String, Object>> login(
        @RequestParam String username,
        @RequestParam String password,
        HttpServletRequest request,
        HttpServletResponse response)
```

**硬编码凭证：**
- 用户名：`admin`
- 密码：`password123`

**安全缺陷：**
1. **硬编码凭证** - 凭证直接写在源代码中，无法更改
2. **无速率限制** - 登录端点没有限制尝试次数，允许暴力破解
3. **明文传输** - 没有HTTPS配置，凭证以明文形式发送

#### 3.2 HTTP头认证绕过
**漏洞位置：** `AuthController.java` 第27-35行

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

**安全缺陷：**
- **致命缺陷** - 任何包含`X-Admin-Header`头的请求都会获得管理员权限
- **无验证** - 头的值可以是任何内容，甚至为空
- **攻击向量：** `curl -X POST http://target/login -H "X-Admin-Header: anything" -d "username=x&password=x"`

#### 3.3 Cookie认证绕过
**漏洞位置：** `AuthController.java` 第37-48行

```java
Cookie[] cookies = request.getCookies();
if (cookies != null) {
    for (Cookie cookie : cookies) {
        if ("bypass_auth".equals(cookie.getName())) {
            response.setHeader("X-Auth-Status", "bypassed");
            // ... 授予管理员权限
        }
    }
}
```

**安全缺陷：**
- **致命缺陷** - 任何包含`bypass_auth`Cookie的请求都会获得管理员权限
- **无签名** - Cookie值可以任意设置
- **攻击向量：** `curl -X POST http://target/login -b "bypass_auth=anything"`

### 会话管理
**文件位置：** `src/main/java/com/example/shannontarget/controller/AuthController.java`

**当前实现：**
- 无Session cookie配置
- 无`HttpOnly`、`Secure`、`SameSite`标志设置
- 认证状态仅通过响应头传递

**安全缺陷：**
- **Cookie安全标志缺失** - 所有Cookie都缺少安全标志，容易被XSS窃取
- **无会话持久化** - 每次请求都需要重新认证
- **响应头状态泄露** - `X-Auth-Status`头暴露了认证状态

### 授权模型
**文件位置：** `src/main/java/com/example/shannontarget/controller/AuthController.java` 第57-67行

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

**安全缺陷：**
- **基于请求头的授权** - 任何人都可以设置此头绕过授权
- **无会话验证** - 不使用服务器端会话存储
- **敏感信息泄露** - 仪表板返回敏感信息

### SSO/OAuth/OIDC流
该应用程序**未实现**任何SSO、OAuth或OIDC身份验证流程。

---

## 4. 数据安全与存储

### 数据库安全
**文件位置：** `src/main/java/com/example/shannontarget/controller/ApiController.java`

**H2数据库配置：**
- 数据库URL：`jdbc:h2:mem:testdb`
- 用户名：`sa`
- 密码：空字符串（无密码）
- 数据库类型：内存数据库

**安全缺陷：**
1. **无密码保护** - 数据库完全开放
2. **内存存储** - 数据在重启后丢失，但运行时可被访问
3. **SQL注入** - 详见第5节攻击面分析

### 数据流安全
**识别到的敏感数据流：**

| 端点 | 数据类型 | 保护措施 | 风险等级 |
|------|----------|----------|----------|
| /login | 用户凭据 | 无 | 严重 |
| /user/search | 用户数据 | 无 | 高 |
| /comment | 用户输入 | 无 | 中 |
| /profile | 用户数据 | 无 | 中 |

### 多租户数据隔离
该应用程序**不实现**多租户功能，所有用户共享同一数据空间。

---

## 5. 攻击面分析

### 5.1 外部入口点详细分析

#### **A. 认证端点**

| 端点 | 方法 | 认证要求 | 文件位置 | 漏洞 |
|------|------|----------|----------|------|
| `/login` | POST | 公开 | AuthController.java:18 | 认证绕过、暴力破解 |
| `/dashboard` | GET | 可绕过 | AuthController.java:57 | 授权绕过 |

#### **B. 命令注入端点**

| 端点 | 方法 | 参数 | 文件位置 | 漏洞 |
|------|------|------|----------|------|
| `/ping` | GET | host | CmdController.java:21 | 命令注入 |
| `/traceroute` | GET | target | CmdController.java:52 | 命令注入 |
| `/nslookup` | GET | domain | CmdController.java:83 | 命令注入 |

**命令注入漏洞详情：**

```java
// CmdController.java 第28行
String command = "ping -n 2 " + host;
ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
```

**攻击向量：**
```
GET /ping?host=127.0.0.1;whoami
GET /traceroute?target=8.8.8.8&&dir
GET /nslookup?domain=example.com%26ipconfig
```

#### **C. SQL注入端点**

| 端点 | 方法 | 参数 | 文件位置 | 漏洞 |
|------|------|------|----------|------|
| `/user/search` | GET | username | ApiController.java:44 | SQL注入 |
| `/user/lookup` | GET | id | ApiController.java:70 | SQL注入 |

**SQL注入漏洞详情：**

```java
// ApiController.java 第55行
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
Statement queryStmt = conn.createStatement();
ResultSet rs = queryStmt.executeQuery(sql);
```

**攻击向量：**
```
GET /user/search?username=admin' OR '1'='1
GET /user/lookup?id=1 OR 1=1
```

#### **D. SSRF端点**

| 端点 | 方法 | 参数 | 文件位置 | 漏洞 |
|------|------|------|----------|------|
| `/fetch` | GET | url | ApiController.java:21 | SSRF |

**SSRF漏洞详情：**

```java
// ApiController.java 第26-28行
String response = restTemplate.getForObject(url, String.class);
return ResponseEntity.ok(Map.of(
    "url", url,
    "response", response
));
```

**攻击向量：**
```
GET /fetch?url=http://169.254.169.254/latest/meta-data/  (AWS元数据)
GET /fetch?url=http://localhost:8080/admin              (内部扫描)
GET /fetch?url=http://internal-api.local/               (内部服务)
```

#### **E. XSS端点**

| 端点 | 方法 | 参数 | 文件位置 | 漏洞 |
|------|------|------|----------|------|
| `/comment` | POST | content | XssController.java:19 | 存储型XSS |
| `/comment` | GET | filter | XssController.java:29 | 反射型XSS |
| `/search` | GET | q | XssController.java:42 | 反射型XSS |
| `/profile` | POST | name, bio | XssController.java:52 | 存储型XSS |

**XSS漏洞详情：**

```java
// XssController.java 第19-25行
comments.add(Map.of(
    "content", content,  // 无任何过滤
    "timestamp", java.time.Instant.now().toString()
));
```

**攻击向量：**
```
POST /comment?content=<script>alert(document.cookie)</script>
GET /search?q=<img src=x onerror=alert(1)>
POST /profile?name=<script>alert(1)</script>&bio=test
```

### 5.2 内部服务通信
- **无内部服务** - 应用程序不与任何内部服务通信
- **外部API调用** - `/fetch`端点允许任意外部URL调用

### 5.3 输入验证模式
- **零输入验证** - 所有用户输入都直接使用，无任何验证
- **无白名单** - 没有URL、命令或SQL输入的白名单
- **无编码** - 输出无任何HTML/URL编码

### 5.4 后台处理
- **无异步任务** - 所有请求同步处理
- **无作业队列** - 不存在后台作业系统

---

## 6. 基础设施与运营安全

### 密钥管理
- **硬编码密钥** - 凭证直接写在代码中
- **无密钥库** - 不使用Java密钥库或外部密钥管理
- **配置文件** - `application.properties` 包含敏感配置（空密码）

**文件位置：** `src/main/resources/application.properties`
```properties
server.port=8080
spring.application.name=shannon-target
```

### 配置安全
- **无HTTPS配置** - 服务器配置中未启用TLS
- **无安全头** - 未配置HSTS、CSP、X-Frame-Options等
- **默认端口** - 使用标准8080端口

### 外部依赖
**Maven依赖分析 (pom.xml)：**
| 依赖 | 版本 | 已知漏洞 |
|------|------|----------|
| spring-boot-starter-web | 3.2.0 | 低风险 |
| spring-boot-starter-thymeleaf | 3.2.0 | 低风险 |
| h2 | 运行时 | 中风险 |

### 监控与日志
- **无安全日志** - 应用程序不记录安全事件
- **无审计追踪** - 没有用户活动审计
- **无入侵检测** - 没有异常行为检测

---

## 7. 代码库整体索引

### 目录结构

```
/app/repos/lumin-20260315-052139-18638/
├── .git/                          # Git版本控制
├── .github/                       # GitHub工作流（空）
├── src/
│   └── main/
│       ├── java/com/example/shannontarget/
│       │   ├── ShannonTargetApplication.java    # 主应用入口
│       │   └── controller/
│       │       ├── AuthController.java          # 认证端点（含漏洞）
│       │       ├── CmdController.java           # 命令注入端点
│       │       ├── XssController.java           # XSS端点
│       │       └── ApiController.java           # SQLi/SSRF端点
│       └── resources/
│           ├── application.properties           # 应用配置
│           └── static/
│               └── index.html                   # 前端SPA
├── pom.xml                                     # Maven配置
├── Dockerfile                                  # 容器构建文件
└── deliverables/                               # 交付物目录
```

### 项目特点
- **标准Maven结构** - 使用标准Java项目组织方式
- **单一模块** - 无多模块Maven配置
- **控制器模式** - 所有端点集中在controller包
- **无测试** - 项目无单元测试或集成测试
- **Docker支持** - 提供Dockerfile用于容器化部署

---

## 8. 关键文件路径

### 配置文件
- `pom.xml` - Maven项目配置和依赖声明
- `src/main/resources/application.properties` - Spring Boot应用配置
- `Dockerfile` - 容器镜像构建定义

### 认证与授权
- `src/main/java/com/example/shannontarget/controller/AuthController.java` - 所有认证相关端点（含认证绕过漏洞）

### API与路由
- `src/main/java/com/example/shannontarget/controller/CmdController.java` - 网络工具端点（命令注入）
- `src/main/java/com/example/shannontarget/controller/XssController.java` - 评论和搜索端点（XSS）
- `src/main/java/com/example/shannontarget/controller/ApiController.java` - 用户查询端点（SQL注入、SSRF）
- `src/main/resources/static/index.html` - 前端单页应用

### 数据模型与数据库交互
- `src/main/java/com/example/shannontarget/controller/ApiController.java` - H2数据库连接和SQL查询（含SQL注入）

### 依赖清单
- `pom.xml` - Java依赖声明

### 敏感数据与密钥处理
- `src/main/java/com/example/shannontarget/controller/AuthController.java` - 硬编码凭证

### 中间件与输入验证
- 所有控制器均无输入验证中间件

### 日志与监控
- 无专门的安全日志配置

### 基础设施与部署
- `Dockerfile` - 容器化部署配置

---

## 9. XSS接收器和渲染上下文

### 存储型XSS

#### `/comment` 端点
- **文件位置：** `src/main/java/com/example/shannontarget/controller/XssController.java` 第19-25行
- **漏洞类型：** 存储型XSS - 用户输入直接存储无过滤
- **渲染上下文：** JSON响应中的body context
- **攻击向量：** `POST /comment?content=<script>alert(1)</script>`

#### `/profile` 端点
- **文件位置：** `src/main/java/com/example/shannontarget/controller/XssController.java` 第52-62行
- **漏洞类型：** 存储型XSS - name和bio参数无过滤
- **渲染上下文：** JSON响应
- **攻击向量：** `POST /profile?name=<img%20src=x%20onerror=alert(1)>&bio=test`

### 反射型XSS

#### `/comment` 筛选参数
- **文件位置：** `src/main/java/com/example/shannontarget/controller/XssController.java` 第29-43行
- **漏洞类型：** 反射型XSS - filter参数直接反映在响应中
- **渲染上下文：** JSON键"filter"的value
- **攻击向量：** `GET /comment?filter=<script>alert(1)</script>`

#### `/search` 查询参数
- **文件位置：** `src/main/java/com/example/shannontarget/controller/XssController.java` 第42-50行
- **漏洞类型：** 反射型XSS - q参数直接反映
- **渲染上下文：** JSON键"query"的value
- **攻击向量：** `GET /search?q=<img%20onerror=alert(1)%20src=x>`

### 前端渲染（index.html）
前端JavaScript对所有端点返回的数据使用`textContent`和`JSON.stringify`进行渲染，但存在以下风险：
1. 评论内容在页面重新加载时可能以不安全方式渲染
2. 搜索结果直接显示给用户
3. 调试信息（如SQL查询）可能泄露

---

## 10. SSRF接收器

### HTTP客户端请求

#### `/fetch` 端点
- **文件位置：** `src/main/java/com/example/shannontarget/controller/ApiController.java` 第18-35行
- **漏洞类型：** SSRF - 用户可控制URL参数直接用于HTTP请求
- **代码片段：**
```java
@GetMapping("/fetch")
public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
    try {
        String response = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(Map.of(
            "url", url,
            "response", response != null ? response : ""
        ));
    } catch (Exception e) {
        return ResponseEntity.badRequest().body(Map.of(
            "url", url,
            "error", e.getMessage()
        ));
    }
}
```

**攻击向量：**

| 目标 | URL | 目的 |
|------|-----|------|
| AWS元数据 | `http://169.254.169.254/latest/meta-data/` | 获取实例信息 |
| GCP元数据 | `http://metadata.google.internal/computeMetadata/v1/` | 获取凭证 |
| 本地端口扫描 | `http://localhost:8080/admin` | 内部扫描 |
| 内部服务 | `http://192.168.1.1:80/` | 内部网络探测 |
| 私有IP | `http://10.0.0.1/` | 私有网络访问 |

**防护缺失：**
- 无URL验证
- 无协议限制（允许file://、ftp://等）
- 无主机名黑名单
- 无IP范围限制

---

## 总结

**Shannon Target** 应用程序是一个存在**严重安全漏洞**的演示应用，适用于渗透测试训练。发现的漏洞按严重程度分类如下：

### 严重漏洞（CRITICAL）
1. 认证绕过（HTTP头和Cookie）
2. 命令注入（3个端点）
3. SQL注入（2个端点）
4. SSRF

### 高危漏洞（HIGH）
1. 存储型XSS
2. 反射型XSS
3. 暴力破解无限制
4. 硬编码凭证

### 中危漏洞（MEDIUM）
1. 缺少安全Headers
2. 无HTTPS配置
3. 数据库无密码保护
4. 无安全日志

该应用程序应仅用于受控的安全测试环境，**不应部署在生产环境或暴露于公共网络**。
