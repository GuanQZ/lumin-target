const http = require('http');
const url = require('url');

const PORT = 8080;

// In-memory "database"
const users = [
  { id: 1, username: 'admin', email: 'admin@example.com', role: 'administrator' },
  { id: 2, username: 'john', email: 'john@example.com', role: 'user' },
  { id: 3, username: 'jane', email: 'jane@example.com', role: 'user' }
];

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;
  
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Header, X-Auth-Status');
  
  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  console.log(`${req.method} ${pathname}`);
  
  // Helper to parse POST body
  const getPostData = () => {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => resolve(body));
      req.on('error', reject);
    });
  };

  // POST /login - Auth bypass vulnerabilities
  if (req.method === 'POST' && pathname === '/login') {
    getPostData().then(body => {
      const params = new URLSearchParams(body);
      const username = params.get('username');
      const password = params.get('password');
      
      // Get cookies
      const cookieHeader = req.headers.cookie || '';
      const cookies = {};
      cookieHeader.split(';').forEach(c => {
        const [k, v] = c.trim().split('=');
        if (k) cookies[k] = v;
      });
      
      // Check for X-Admin-Header bypass (AUTHZ-VULN-03)
      const adminHeader = req.headers['x-admin-header'];
      if (adminHeader !== undefined) {
        res.setHeader('X-Auth-Status', 'bypassed');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Login bypassed via header',
          user: 'admin',
          role: 'administrator'
        }));
        return;
      }
      
      // Check for bypass_auth cookie bypass (AUTHZ-VULN-04)
      if (cookies['bypass_auth']) {
        res.setHeader('X-Auth-Status', 'bypassed');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Login bypassed via cookie',
          user: 'admin',
          role: 'administrator'
        }));
        return;
      }
      
      // Normal authentication
      if (username === 'admin' && password === 'password123') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: 'Login successful',
          user: username,
          role: 'user'
        }));
        return;
      }
      
      // Invalid credentials
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: false,
        message: 'Invalid credentials'
      }));
    });
    return;
  }

  // GET /dashboard - Workflow bypass vulnerability (AUTHZ-VULN-05)
  if (req.method === 'GET' && pathname === '/dashboard') {
    const authStatus = req.headers['x-auth-status'];
    if (authStatus === 'bypassed') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        message: 'Welcome to admin dashboard',
        data: 'Sensitive information here'
      }));
      return;
    }
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ message: 'Access denied' }));
    return;
  }

  // GET /user/lookup - IDOR vulnerability (AUTHZ-VULN-01)
  if (req.method === 'GET' && pathname === '/user/lookup') {
    const id = query.id;
    // No ownership check - direct SQL equivalent
    const user = users.find(u => u.id === parseInt(id));
    if (user) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        query: `SELECT * FROM users WHERE id = ${id}`,
        results: [user]
      }));
    } else {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        id: id,
        error: 'User not found'
      }));
    }
    return;
  }

  // GET /user/search - IDOR/SQLi vulnerability (AUTHZ-VULN-02)
  if (req.method === 'GET' && pathname === '/user/search') {
    const username = query.username;
    // No authorization check - SQL injection also possible
    // Simulating SQL injection by checking for '
    let results = users;
    if (username && !username.includes("'")) {
      results = users.filter(u => u.username.toLowerCase().includes(username.toLowerCase()));
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      query: `SELECT * FROM users WHERE username = '${username}'`,
      results: results
    }));
    return;
  }

  // GET /fetch - SSRF vulnerability (not authz but for completeness)
  if (req.method === 'GET' && pathname === '/fetch') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      url: query.url,
      response: 'SSRF - URL fetched (simulated)'
    }));
    return;
  }

  // Default: 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`Shannon Target模拟服务器运行在 http://localhost:${PORT}`);
  console.log('可用端点:');
  console.log('  POST /login - 登录 (支持 X-Admin-Header 和 bypass_auth cookie 绕过)');
  console.log('  GET /dashboard - 仪表板 (支持 X-Auth-Status 绕过)');
  console.log('  GET /user/lookup?id=X - 用户查询 (IDOR)');
  console.log('  GET /user/search?username=X - 用户搜索 (IDOR/SQLi)');
  console.log('  GET /fetch?url=X - URL获取 (SSRF)');
});
