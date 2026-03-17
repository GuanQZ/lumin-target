# 侦察交付物：Shannon Target 应用攻击面分析

## 0) 如何阅读本文档

本侦察报告提供了 **Shannon Target** 应用完整的攻击面映射，特别关注授权和权限提升机会。

**关键分析章节说明：**

- **Section 4（API 端点清单）：** 包含每个端点的授权详情 - 重点关注 "Required Role" 和 "Object ID Parameters" 列以识别 IDOR 候选点。
- **Section 6.4（防御目录）：** 授权控制目录 - 在分析漏洞前理解每个防御机制的含义。
- **Section 7（角色与权限架构）：** 完整的角色层级和权限映射 - 用于理解权限结构并识别权限提升目标。
- **Section 8（授权漏洞候选）：** 预先排序的端点列表，用于水平、垂直和基于上下文的授权测试。

**网络映射使用说明（Section 6）：** 实体/流映射显示系统边界和数据敏感度级别。特别注意带有授权防御的流和处理个人身份信息/敏感数据的实体。

**测试优先级顺序：** 从 Section 8 的高优先级水平候选开始，然后测试每个角色级别的垂直权限提升端点，最后是基于上下文的工作流绕过。

---

## 1. 执行摘要

**目标应用概述：** Shannon Target 是一个基于 Spring Boot 3.2.0 和 Java 17 构建的 Web 应用，故意包含了多个安全漏洞用于安全测试训练。

**核心发现：**
- **技术栈：** Spring Boot 3.2.0 + Java 17 + H2 内存数据库 + Thymeleaf
- **端点数量：** 10 个 API 端点（不含静态资源）
- **安全评级：** **极不安全** - 应用完全缺乏认证和授权机制

**关键安全问题汇总：**
| 类别 | 数量 | 严重程度 |
|------|------|----------|
| 命令注入 | 3 | 🔴 严重 |
| SQL 注入 | 2 | 🔴 严重 |
| SSRF | 1 | 🔴 严重 |
| XSS | 4 | 🟠 高危 |
| 认证绕过 | 3 | 🔴 严重 |

**应用特点：**
- ❌ 无 Spring Security 依赖
- ❌ 无认证中间件
- ❌ 无授权框架
- ❌ 无输入验证
- ❌ 无安全响应头

---

## 2. 技术与服务映射

### 技术栈详情

| 组件 | 版本/详情 | 说明 |
|------|----------|------|
| **编程语言** | Java 17 | 后端核心语言 |
| **Web 框架** | Spring Boot 3.2.0 | REST API 框架 |
| **模板引擎** | Thymeleaf | 未发现 SSTI |
| **数据库** | H2（内存数据库） | 数据存储，重启后丢失 |
| **前端** | 原生 HTML/JS | 静态资源 |
| **构建工具** | Maven 3.9 | 依赖管理 |
| **容器化** | Docker | 部署环境 |

### 架构模式

```
shannon-target/
├── src/main/java/com/example/shannontarget/
│   ├── ShannonTargetApplication.java     # Spring Boot 主入口
│   └── controller/
│       ├── XssController.java            # XSS 漏洞端点（4个）
│       ├── CmdController.java             # 命令注入端点（3个）
│       ├── AuthController.java            # 认证端点（2个）
│       └── ApiController.java            # SSRF/SQL注入端点（3个）
├── src/main/resources/
│   ├── application.properties             # 应用配置
│   └── static/index.html                  # 前端管理界面
├── pom.xml                               # Maven 依赖配置
└── Dockerfile                            # Docker 构建配置
```

### 网络端口配置

| 配置项 | 值 |
|--------|-----|
| HTTP 端口 | 8080 |
| 应用名称 | shannon-target |
| 数据库 URL | jdbc:h2:mem:testdb |

---

## 3. 认证与会话管理流程

### 3.1 认证端点与机制

**入口点（认证入口点）：**

| 端点 | 方法 | 认证方式 | 位置 |
|------|------|----------|------|
| `/login` | POST | 用户名/密码 + 认证绕过 | AuthController.java:24-60 |
| `/dashboard` | GET | Header 检查 | AuthController.java:62-73 |

### 3.1.1 认证流程详解

**认证流程步骤：**

1. **Header 认证绕过检查** (AuthController.java:28-33)
   - 检查 `X-Admin-Header` 请求头
   - 如果存在任意值 → 返回管理员角色

2. **Cookie 认证绕过检查** (AuthController.java:36-47)
   - 检查 `bypass_auth` Cookie
   - 如果存在 → 返回管理员角色

3. **普通凭证验证** (AuthController.java:50-55)
   - 硬编码凭证：`admin` / `password123`
   - 成功返回 `user` 角色

4. **Session 状态响应**
   - 设置 `X-Auth-Status: bypassed` 响应头

### 3.2 角色分配流程

**角色分配：**

| 认证方式 | 分配角色 | 代码位置 |
|----------|----------|----------|
| Header 绕过 | `administrator` | AuthController.java:34 |
| Cookie 绕过 | `administrator` | AuthController.java:45 |
| 正常登录 | `user` | AuthController.java:53 |
| 默认角色 | 无 | 不适用 |

**角色确定方式：** 响应 JSON 中硬编码返回角色字符串，无持久化存储。

### 3.3 权限存储与验证

**存储位置：** 无持久化存储

- ❌ 无 JWT Token
- ❌ 无 Session 存储
- ❌ 无数据库用户表

**验证方式：** 仅在 `/dashboard` 端点检查 `X-Auth-Status` 请求头

**代码实现：**
```java
// AuthController.java:62-73
@GetMapping("/dashboard")
public ResponseEntity<Map<String, Object>> dashboard(HttpServletRequest request) {
    String authStatus = request.getHeader("X-Auth-Status");
    if ("bypassed".equals(authStatus)) {
        return ResponseEntity.ok(Map.of(...));
    }
    return ResponseEntity.status(403).body(Map.of(...));
}
```

### 3.4 认证绕过方法汇总

| 绕过方式 | 触发条件 | 代码位置 | 风险等级 |
|----------|----------|----------|----------|
| X-Admin-Header | 请求包含任意值的 `X-Admin-Header` 头 | AuthController.java:28-33 | 🔴 严重 |
| bypass_auth Cookie | 请求包含名为 `bypass_auth` 的 Cookie | AuthController.java:36-47 | 🔴 严重 |
| X-Auth-Status | 请求直接设置 `X-Auth-Status: bypassed` 头 | AuthController.java:62-73 | 🔴 严重 |

### 3.5 硬编码凭证

**位置：** AuthController.java:14-15
```java
private static final String VALID_USERNAME = "admin";
private static final String VALID_PASSWORD = "password123";
```

---

## 4. API 端点清单

**API 端点完整清单（网络可访问）：**

| 方法 | 端点路径 | 所需角色 | 对象ID参数 | 授权机制 | 描述与代码位置 |
|--------|---------------|---------------|----------------------|-------------------------|----------------------------|
| POST | `/login` | 匿名 | 无 | 无 | 用户登录 - AuthController.java:24 |
| GET | `/dashboard` | 匿名（可绕过） | 无 | X-Auth-Status Header | 仪表板 - AuthController.java:62 |
| GET | `/ping` | 匿名 | host | 无 | Ping 命令执行 - CmdController.java:21 |
| GET | `/traceroute` | 匿名 | target | 无 | 路由追踪 - CmdController.java:49 |
| GET | `/nslookup` | 匿名 | domain | 无 | DNS 查询 - CmdController.java:77 |
| GET | `/fetch` | 匿名 | url | 无 | URL 抓取（SSRF）- ApiController.java:21 |
| GET | `/user/search` | 匿名 | username | 无 | 用户搜索（SQLi）- ApiController.java:46 |
| GET | `/user/lookup` | 匿名 | id | 无 | 用户查询（SQLi）- ApiController.java:82 |
| POST | `/comment` | 匿名 | content | 无 | 添加评论（XSS）- XssController.java:20 |
| GET | `/comment` | 匿名 | filter | 无 | 评论列表（XSS）- XssController.java:34 |
| GET | `/search` | 匿名 | q | 无 | 搜索（XSS）- XssController.java:54 |
| POST | `/profile` | 匿名 | name, bio | 无 | 资料更新（XSS）- XssController.java:65 |
| GET | `/` | 匿名 | 无 | 无 | 静态首页 - static/index.html |

**注意：** 所有端点均可匿名访问，无任何认证或授权检查。

---

## 5. 漏洞分析的潜在输入向量

### 5.1 URL 参数（查询参数）

| 端点 | 参数名 | 用途 | 漏洞类型 |
|------|--------|------|----------|
| `/ping` | `host` | 目标主机 | 命令注入 |
| `/traceroute` | `target` | 目标地址 | 命令注入 |
| `/nslookup` | `domain` | 域名 | 命令注入 |
| `/fetch` | `url` | 目标URL | SSRF |
| `/user/search` | `username` | 用户名 | SQL注入 |
| `/user/lookup` | `id` | 用户ID | SQL注入 |
| `/comment` | `filter` | 过滤关键词 | 反射型XSS |
| `/search` | `q` | 搜索词 | 反射型XSS |

### 5.2 POST 请求体字段（表单数据）

| 端点 | 参数名 | 用途 | 漏洞类型 |
|------|--------|------|----------|
| `/login` | `username` | 用户名 | 无 |
| `/login` | `password` | 密码 | 无 |
| `/comment` | `content` | 评论内容 | 存储型XSS |
| `/profile` | `name` | 姓名 | 反射型XSS |
| `/profile` | `bio` | 个人简介 | 反射型XSS |

### 5.3 HTTP 头

| 端点 | 头名称 | 用途 | 漏洞类型 |
|------|-----------|------|----------|
| `/login` | `X-Admin-Header` | 认证绕过 | 认证绕过 |
| `/dashboard` | `X-Auth-Status` | 认证状态检查 | 认证绕过 |

### 5.4 Cookie 值

| 端点 | Cookie 名称 | 用途 | 漏洞类型 |
|------|-----------|------|----------|
| `/login` | `bypass_auth` | 认证绕过 | 认证绕过 |

---

## 6. 网络与交互映射

### 6.1 实体

| 标题 | 类型 | 区域 | 技术 | 数据 | 备注 |
|-------|------|------|------|------|-------|
| **WebApp** | 服务 | 应用 | Spring Boot 3.2.0 / Java 17 | 个人身份信息、令牌 | 主应用服务器 - 处理所有请求 |
| **H2-Database** | 数据存储 | 数据 | H2（内存） | 个人身份信息 | 内存数据库 - 存储用户数据 |
| **User-Browser** | 外部资产 | 互联网 | 浏览器 | 公开 | 客户端浏览器 |
| **Cloud-Metadata** | 第三方 | 第三方 | HTTP | 密钥 | 云元数据端点（169.254.169.254） |

### 6.2 实体元数据

| 标题 | 元数据 |
|-------|----------|
| WebApp | 端口：8080；端点：10+；认证：无；依赖项：H2-Database |
| H2-Database | 引擎：H2；URL：jdbc:h2:mem:testdb；凭证：sa/（空）；暴露：仅内部 |
| User-Browser | 客户端：Chrome/Firefox；协议：HTTP；认证：无需 |

### 6.3 流（连接）

| 从 → 到 | 通道 | 路径/端口 | 防御机制 | 触及数据 |
|-----------|---------|-----------|---------|---------|
| User-Browser → WebApp | HTTP | :8080/* | 无 | 公开 |
| WebApp → H2-Database | JDBC | mem:testdb | 无 | 个人身份信息 |
| WebApp → Cloud-Metadata | HTTP | 169.254.169.254/* | 无（SSRF） | 密钥 |

### 6.4 防御目录

| 防御名称 | 类别 | 说明 |
|------------|----------|-----------|
| 无 | 认证 | **完全无认证** - 所有端点可匿名访问 |
| 无 | 授权 | **完全无授权** - 无 RBAC/ACL 实现 |
| 无 | 网络 | **无防火墙** - 无 IP 白名单/黑名单 |
| 无 | 速率限制 | **无速率限制** - 暴力破解风险 |

---

## 7. 角色与权限架构

### 7.1 发现的角色

| 角色名称 | 权限级别 | 作用域/域 | 代码实现 |
|-----------|-----------------|--------------|---------------------|
| `anon` | 0 | 全局 | 无需认证 |
| `user` | 1 | 全局 | 正常登录返回（AuthController.java:53） |
| `administrator` | 5 | 全局 | 认证绕过返回（AuthController.java:34, 45） |

### 7.2 权限结构

```
权限顺序（→ 表示"可以访问"）：
anon（0）→ user（1）→ administrator（5）

注意：由于无真正的授权机制，任何用户都可以通过绕过方法获得 administrator 权限。
```

### 7.3 角色入口点

| 角色 | 默认登录页面 | 可访问路由模式 | 认证方式 |
|------|---------------------|---------------------------|----------------------|
| anon | `/` | `/`, `/login`, `/ping`, `/traceroute`, `/nslookup`, `/fetch`, `/user/*`, `/comment`, `/search`, `/profile` | 无 |
| user | （无） | 与 anon 相同 | 硬编码凭证（admin/password123） |
| administrator | `/dashboard` | 与 anon 相同 + `/dashboard` | Header/Cookie 绕过 |

### 7.4 角色到代码的映射

| 角色 | 中间件/防御 | 权限检查 | 存储位置 |
|------|-------------------|-------------------|------------------|
| anon | 无 | 无 | 无 |
| user | 无 | 硬编码：VALID_USERNAME.equals(username) && VALID_PASSWORD.equals(password) | 响应 JSON（无持久化） |
| administrator | 无 | 检查 X-Admin-Header != null 或 bypass_auth cookie 存在 | 响应 JSON（无持久化） |

---

## 8. 授权漏洞候选

### 8.1 水平权限提升候选

**水平权限提升候选端点：**

由于应用无真正的用户隔离和对象所有权验证，以下端点理论上可被测试：

| 优先级 | 端点模式 | 对象ID参数 | 数据类型 | 敏感度 | 备注 |
|----------|-----------------|---------------------|-----------|-------------|-------|
| **高** | `/user/lookup?id={id}` | id | user_data | 高 | SQL注入可获取任意用户数据 |
| **高** | `/user/search?username={name}` | username | user_data | 高 | SQL注入可枚举用户 |
| **中** | `/comment?filter={filter}` | filter | user_content | 中 | 反射型XSS |
| **低** | `/search?q={query}` | q | user_input | 低 | 反射型XSS |

### 8.2 垂直权限提升候选

**垂直权限提升候选端点：**

| 目标角色 | 端点模式 | 功能 | 风险等级 | 绕过方法 |
|-------------|------------------|---------------|-------------|---------------|
| admin | `/dashboard` | 管理仪表板 | 🔴 严重 | 发送 X-Auth-Status: bypassed header |
| admin | `/login` | 登录接口 | 🔴 严重 | 发送 X-Admin-Header 或 bypass_auth cookie |
| user | 所有业务端点 | 任何功能 | 🔴 严重 | 无需认证即可访问 |

### 8.3 基于上下文的授权候选

**基于上下文的授权候选端点：**

| 工作流 | 端点 | 预期前置状态 | 绕过可能性 |
|----------|----------|---------------------|------------------|
| 认证流程 | `/dashboard` | 应先通过 `/login` | 直接发送 header 绕过 |
| 命令执行 | `/ping`, `/traceroute`, `/nslookup` | 无需前置条件 | 直接访问执行任意命令 |
| 数据查询 | `/user/search`, `/user/lookup` | 无需前置条件 | 直接注入获取全部数据 |
| URL抓取 | `/fetch` | 无需前置条件 | 直接访问内部服务 |

---

## 9. 注入源（命令注入、SQL 注入、SSRF、XSS）

### 9.1 命令注入源

**命令注入源（3个）：**

| # | 端点 | 文件:行 | 输入向量 | Sink | 数据流 |
|---|----------|-----------|--------------|------|-----------|
| 1 | `/ping` | CmdController.java:23-47 | `host` 参数 | ProcessBuilder | @RequestParam → 字符串拼接 → pb.start() |
| 2 | `/traceroute` | CmdController.java:50-77 | `target` 参数 | ProcessBuilder | @RequestParam → 字符串拼接 → pb.start() |
| 3 | `/nslookup` | CmdController.java:80-107 | `domain` 参数 | ProcessBuilder | @RequestParam → 字符串拼接 → pb.start() |

**漏洞代码示例：**
```java
// CmdController.java:23-24
String command = "ping -n 2 " + host;
ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
```

### 9.2 SQL 注入源

**SQL 注入源（2个）：**

| # | 端点 | 文件:行 | 输入向量 | Sink | 数据流 |
|---|----------|-----------|--------------|------|-----------|
| 1 | `/user/search` | ApiController.java:53-55 | `username` 参数 | Statement.executeQuery() | @RequestParam → 字符串拼接 → SQL 查询 |
| 2 | `/user/lookup` | ApiController.java:99-100 | `id` 参数 | Statement.executeQuery() | @RequestParam → 字符串拼接 → SQL 查询 |

**漏洞代码示例：**
```java
// ApiController.java:53-55
String sql = "SELECT * FROM users WHERE username = '" + username + "'";
Statement queryStmt = conn.createStatement();
ResultSet rs = queryStmt.executeQuery(sql);
```

### 9.3 SSRF 源

**服务器端请求伪造源（1个）：**

| # | 端点 | 文件:行 | 输入向量 | Sink | 数据流 |
|---|----------|-----------|--------------|------|-----------|
| 1 | `/fetch` | ApiController.java:21-36 | `url` 参数 | RestTemplate.getForObject() | @RequestParam → URL 对象 → HTTP 请求 |

**漏洞代码示例：**
```java
// ApiController.java:28
String response = restTemplate.getForObject(url, String.class);
```

**攻击目标：**
- 云元数据：`http://169.254.169.254/latest/meta-data/`
- 内部服务：`http://localhost`、`http://127.0.0.1`
- 内部端口：`http://192.168.1.1:6379`

### 9.4 XSS 源

**跨站脚本源（4个）：**

| # | 端点 | 文件:行 | 输入向量 | 类型 | 数据流 |
|---|----------|-----------|--------------|------|-----------|
| 1 | `/comment`（POST） | XssController.java:20-31 | `content` 参数 | 存储型 | @RequestParam → 内存列表 → JSON 响应 |
| 2 | `/comment`（GET） | XssController.java:34-51 | `filter` 参数 | 反射型 | @RequestParam → JSON 响应 |
| 3 | `/search` | XssController.java:54-62 | `q` 参数 | 反射型 | @RequestParam → JSON 响应 |
| 4 | `/profile` | XssController.java:65-76 | `name`、`bio` 参数 | 反射型 | @RequestParam → JSON 响应 |

**漏洞代码示例：**
```java
// XssController.java:28
return ResponseEntity.ok(Map.of(
    "content", content,  // 无编码！
    "timestamp", ...
));
```

---

## 10. 总结与测试优先级

### 测试优先级建议

**第一优先级 - 严重：**
1. 命令注入测试（`/ping`、`/traceroute`、`/nslookup`）
2. SQL 注入测试（`/user/search`、`/user/lookup`）
3. SSRF 测试（`/fetch`）
4. 认证绕过测试（`/login`、`/dashboard`）

**第二优先级 - 高危：**
5. XSS 测试（`/comment`、`/search`、`/profile`）

### 关键发现总结

- ✅ 应用为安全测试靶场，故意包含漏洞
- ❌ 完全无认证机制
- ❌ 完全无授权机制
- ❌ 无输入验证
- ❌ 无安全响应头

---

*报告生成时间：完整攻击面分析完成*
*交付物类型：侦察*
