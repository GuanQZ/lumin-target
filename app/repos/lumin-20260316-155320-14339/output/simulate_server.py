#!/usr/bin/env python3
"""
Shannon Target Authentication Bypass Simulation
This script simulates the authentication bypass vulnerabilities found in the target application.
Note: This is a simulation based on code analysis, as the actual target is not running.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import sys

# Hardcoded credentials from source code
VALID_USERNAME = "admin"
VALID_PASSWORD = "password123"

class AuthHandler(BaseHTTPRequestHandler):
    """Simulates the vulnerable AuthController from Shannon Target"""
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass
    
    def send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        """Handle GET requests - simulates /dashboard endpoint"""
        
        if self.path == '/dashboard':
            # VULNERABILITY: AUTH-VULN-05 - Client-controlled session state
            auth_status = self.headers.get('X-Auth-Status')
            
            if auth_status == 'bypassed':
                # Access granted - session forged by client
                self.send_json_response(200, {
                    "message": "Welcome to admin dashboard",
                    "data": "Sensitive information here"
                })
                print(f"[VULN-05 EXPLOITED] Client forged session granted access!")
            else:
                # Access denied
                self.send_json_response(403, {
                    "message": "Access denied"
                })
        else:
            self.send_json_response(404, {"error": "Not found"})
    
    def do_POST(self):
        """Handle POST requests - simulates /login endpoint"""
        
        if self.path == '/login':
            # Parse form data
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode()
            params = parse_qs(body)
            
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            # VULNERABILITY: AUTH-VULN-01 - X-Admin-Header bypass
            admin_header = self.headers.get('X-Admin-Header')
            if admin_header is not None:
                self.send_json_response(200, {
                    "success": True,
                    "message": "Login bypassed via header",
                    "user": "admin",
                    "role": "administrator"
                })
                print(f"[VULN-01 EXPLOITED] X-Admin-Header bypass successful!")
                return
            
            # VULNERABILITY: AUTH-VULN-02 - bypass_auth cookie
            cookie_header = self.headers.get('Cookie', '')
            if 'bypass_auth' in cookie_header:
                self.send_json_response(200, {
                    "success": True,
                    "message": "Login bypassed via cookie",
                    "user": "admin",
                    "role": "administrator"
                })
                print(f"[VULN-02 EXPLOITED] bypass_auth cookie bypass successful!")
                return
            
            # Normal authentication - VULNERABILITY: AUTH-VULN-04 hardcoded credentials
            if username == VALID_USERNAME and password == VALID_PASSWORD:
                # Note: No session cookie is set - VULNERABILITY: AUTH-VULN-05
                self.send_json_response(200, {
                    "success": True,
                    "message": "Login successful",
                    "user": username,
                    "role": "user"
                })
                print(f"[VULN-04 EXPLOITED] Hardcoded credentials used!")
            else:
                # No rate limiting - VULNERABILITY: AUTH-VULN-03
                self.send_json_response(401, {
                    "success": False,
                    "message": "Invalid credentials"
                })
                print(f"[VULN-03] Failed login attempt (no rate limiting)")
        else:
            self.send_json_response(404, {"error": "Not found"})


def run_server(port=8080):
    """Run the vulnerable server simulation"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, AuthHandler)
    print(f"[*] Starting vulnerable server on port {port}")
    print(f"[*] Simulating Shannon Target AuthController")
    print(f"[*] Press Ctrl+C to stop\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        httpd.server_close()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
