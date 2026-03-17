# 网络可访问入口点分析报告

## 项目概述
- **项目名称**: shannon-target (Shannon Target)
- **技术栈**: Spring Boot 3.2.0 + Java 17
- **服务器端口**: 8080 (默认配置于 `application.properties`)
- **项目类型**: 靶场应用 - 用于安全测试
- **前端**: 静态HTML (`index.html`)

---

## 一、API端点完整列表

### 1. 认证相关端点 (AuthController)

| 文件路径 | 路由 | HTTP方法 | 认证级别 | 漏洞描述 |
|----------|------|----------|----------|----------|
| `src/main/java/com/example/shannontarget/controller/AuthController.java` | `/login` | POST | **公开** | 认证绕过漏洞 - 可通过 `X-Admin-Header` 头或 `bypass_auth` cookie绕过 |

**详细说明:**
- 默认凭据: `admin` / `password123`
- 绕过方法1: 请求头 `X-Admin-Header: 任意值`
- 绕过方法2: Cookie `bypass_auth=任意值`
- 无速率限制 - 可暴力破解

| 文件路径 | 路由 | HTTP方法 | 认证级别 | 漏洞描述 |
|----------|------|----------|----------|----------|
| `src/main/java/com/example/shannontarget/controller/AuthController.java` | `/dashboard` | GET | 伪**保护** | 可通过上述认证绕过绕过 |

---

### 2. 命令注入端点 (CmdController)

| 文件路径 | 路由 | HTTP方法 | 参数 | 认证级别 | 漏洞描述 |
|----------|------|----------|------|----------|----------|
| `src/main/java/com/example/shannontarget/controller/CmdController.java` | `/ping` | GET | `host` | **公开** | 命令注入 - 直接拼接用户输入到系统命令 |
| `src/main/java/com/example/shannontarget/controller/CmdController.java` | `/traceroute` | GET | `target` | **公开** | 命令注入 |
| `src/main/java/com/example/shannontarget/controller/CmdController.java` | `/nslookup` | GET | `domain` | **公开** | 命令注入 |

**攻击示例:**
```
GET /ping?host=127.0.0.1;whoami
GET /traceroute?target=8.8.8.8;cat%20/etc/passwd
GET /nslookup?domain=example.com&dir
```

---

### 3. SQL注入/SSRF端点 (ApiController)

| 文件路径 | 路由 | HTTP方法 | 参数 | 认证级别 | 漏洞描述 |
|----------|------|----------|------|----------|----------|
| `src/main/java/com/example/shannontarget/controller/ApiController.java` | `/fetch` | GET | `url` | **公开** | SSRF漏洞 - 可访问内部服务/云元数据 |
| `src/main/java/com/example/shannontarget/controller/ApiController.java` | `/user/search` | GET | `username` | **公开** | SQL注入 - 字符串拼接 |
| `src/main/java/com/example/shannontarget/controller/ApiController.java` | `/user/lookup` | GET | `id` | **公开** | SQL注入 - 数字型 |

**攻击示例:**
```
# SSRF - 访问云元数据
GET /fetch?url=http://169.254.169.254/latest/meta-data/

# SQL注入
GET /user/search?username=' OR '1'='1
GET /user/lookup?id=1 UNION SELECT * FROM users
```

---

### 4. XSS端点 (XssController)

| 文件路径 | 路由 | HTTP方法 | 参数 | 认证级别 | 漏洞描述 |
|----------|------|----------|------|----------|----------|
| `src/main/java/com/example/shannontarget/controller/XssController.java` | `/comment` | POST | `content` | **公开** | 存储型XSS - 无输入过滤 |
| `src/main/java/com/example/shannontarget/controller/XssController.java` | `/comment` | GET | `filter` | **公开** | 反射型XSS |
| `src/main/java/com/example/shannontarget/controller/XssController.java` | `/search` | GET | `q` | **公开** | 反射型XSS |
| `src/main/java/com/example/shannontarget/controller/XssController.java` | `/profile` | POST | `name`, `bio` | **公开** | 反射型XSS |

**攻击示例:**
```
POST /comment?content=<script>alert(1)</script>
GET /search?q=<img src=x onerror=alert(1)>
POST /profile?name=<script>alert(1)</script>&bio=test
```

---

### 5. Web前端入口

| 文件路径 | 路由 | 类型 | 认证级别 |
|----------|------|------|----------|
| `src/main/resources/static/index.html` | `/` (根路径) | HTML | **公开** |
| `src/main/resources/static/index.html` | `/index.html` | HTML | **公开** |

---

## 二、认证级别汇总

| 认证级别 | 端点数量 | 端点列表 |
|----------|----------|----------|
| **公开 (无认证)** | 13 | `/login`, `/dashboard`, `/ping`, `/traceroute`, `/nslookup`, `/fetch`, `/user/search`, `/user/lookup`, `/comment`, `/search`, `/profile`, `/`, `/index.html` |
| **需要认证** | 0 | 无 |
| **总计** | 13 | 全部公开 |

---

## 三、API Schema 文件

**结论: 无API Schema文件**

- ❌ 未找到 OpenAPI/Swagger JSON/YAML 文件
- ❌ 未找到 GraphQL Schema 文件  
- ❌ 未找到 JSON Schema 文件
- ❌ 未配置 SpringDoc OpenAPI
- ❌ 未配置 Springfox Swagger

**搜索的文件模式:**
- `**/*.yaml`, `**/*.yml`, `**/*.json`
- `**/*.graphql`, `**/*.gql`
- `**/openapi*.yaml`, `**/swagger*.json`

---

## 四、Spring Boot 入口点

| 文件路径 | 说明 |
|----------|------|
| `src/main/java/com/example/shannontarget/ShannonTargetApplication.java` | Spring Boot 主类 - 包含 `@SpringBootApplication` |

---

## 五、潜在攻击面分析

### 高危端点 (可直接获取系统权限)

| 端点 | 风险类型 | 危害等级 | CVSS |
|------|----------|----------|------|
| `/ping`, `/traceroute`, `/nslookup` | 命令注入 | **严重** | 10.0 |
| `/fetch` | SSRF | **严重** | 9.1 |
| `/user/search`, `/user/lookup` | SQL注入 | **严重** | 9.8 |
| `/login` | 认证绕过 | **高危** | 8.6 |

### 中危端点 (可执行进一步攻击)

| 端点 | 风险类型 | 危害等级 |
|------|----------|----------|
| `/comment` | 存储型XSS | 中危 |
| `/search`, `/profile` | 反射型XSS | 中危 |

---

## 六、数据库信息

- **数据库**: H2 内存数据库
- **JDBC URL**: `jdbc:h2:mem:testdb`
- **用户名**: `sa`
- **密码**: 空
- **表结构**:
  ```sql
  CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255), role VARCHAR(255))
  ```
- **默认用户**: 
  - admin (id=1, role=administrator)
  - john (id=2, role=user)
  - jane (id=3, role=user)

---

## 七、总结

这是一个**故意设计存在安全漏洞的靶场应用**，所有网络入口点均为**公开访问**，存在以下严重安全问题：

1. **命令注入** - 3个端点 (ping, traceroute, nslookup)
2. **SSRF** - 1个端点 (fetch)
3. **SQL注入** - 2个端点 (user/search, user/lookup)
4. **认证绕过** - 2个端点 (login, dashboard)
5. **XSS** - 4个端点 (comment x2, search, profile)

**渗透测试建议:**
- 优先测试命令注入，可直接获取服务器shell
- SSRF可尝试访问云服务商元数据(169.254.169.254)
- SQL注入可尝试获取数据库完整数据
- 认证绕过可获得管理员权限
