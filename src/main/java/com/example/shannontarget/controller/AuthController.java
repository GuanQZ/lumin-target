package com.example.shannontarget.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class AuthController {

    // Hardcoded credentials for normal login
    private static final String VALID_USERNAME = "admin";
    private static final String VALID_PASSWORD = "password123";

    /**
     * Login endpoint - vulnerable to authentication bypass
     * Vulnerability: If X-Admin-Header is present with any value, authentication is bypassed
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletRequest request,
            HttpServletResponse response) {

        // Check for bypass header - vulnerability: allows admin access without valid credentials
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

        // Check for bypass cookie - vulnerability: allows admin access without valid credentials
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("bypass_auth".equals(cookie.getName())) {
                    response.setHeader("X-Auth-Status", "bypassed");
                    return ResponseEntity.ok(Map.of(
                        "success", true,
                        "message", "Login bypassed via cookie",
                        "user", "admin",
                        "role", "administrator"
                    ));
                }
            }
        }

        // Normal authentication (vulnerable to brute force - no rate limiting)
        if (VALID_USERNAME.equals(username) && VALID_PASSWORD.equals(password)) {
            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Login successful",
                "user", username,
                "role", "user"
            ));
        }

        return ResponseEntity.status(401).body(Map.of(
            "success", false,
            "message", "Invalid credentials"
        ));
    }

    /**
     * Protected endpoint - should require authentication
     */
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
}
