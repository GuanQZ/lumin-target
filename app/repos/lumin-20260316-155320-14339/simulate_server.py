#!/usr/bin/env python3
"""
Shannon Target Authentication Bypass Simulation
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import sys

VALID_USERNAME = "admin"
VALID_PASSWORD = "password123"

class AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_GET(self):
        if self.path == '/dashboard':
            auth_status = self.headers.get('X-Auth-Status')
            if auth_status == 'bypassed':
                self.send_json_response(200, {"message": "Welcome to admin dashboard", "data": "Sensitive information here"})
            else:
                self.send_json_response(403, {"message": "Access denied"})
        else:
            self.send_json_response(404, {"error": "Not found"})
    
    def do_POST(self):
        if self.path == '/login':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode()
            params = parse_qs(body)
            username = params.get('username', [''])[0]
            password = params.get('password', [''])[0]
            
            admin_header = self.headers.get('X-Admin-Header')
            if admin_header is not None:
                self.send_json_response(200, {"success": True, "message": "Login bypassed via header", "user": "admin", "role": "administrator"})
                return
            
            cookie_header = self.headers.get('Cookie', '')
            if 'bypass_auth' in cookie_header:
                self.send_json_response(200, {"success": True, "message": "Login bypassed via cookie", "user": "admin", "role": "administrator"})
                return
            
            if username == VALID_USERNAME and password == VALID_PASSWORD:
                self.send_json_response(200, {"success": True, "message": "Login successful", "user": username, "role": "user"})
            else:
                self.send_json_response(401, {"success": False, "message": "Invalid credentials"})
        else:
            self.send_json_response(404, {"error": "Not found"})

def run_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, AuthHandler)
    print(f"Server running on port {port}")
    httpd.serve_forever()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run_server(port)
