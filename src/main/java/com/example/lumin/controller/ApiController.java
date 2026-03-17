package com.example.lumin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.sql.*;
import java.util.*;

@RestController
public class ApiController {

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * SSRF vulnerability - URL parameter is used directly in HTTP request without validation
     * Can be used to access internal services, cloud metadata, etc.
     */
    @GetMapping("/fetch")
    public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
        try {
            // Vulnerability: No URL validation - accepts any URL including internal ones
            // Can access: http://169.254.169.254/ (cloud metadata), http://localhost, etc.
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

    /**
     * SQL Injection vulnerability - direct string concatenation in SQL query
     * Username parameter is not sanitized
     */
    @GetMapping("/user/search")
    public ResponseEntity<Map<String, Object>> searchUser(@RequestParam String username) {
        // Using H2 in-memory database
        String url = "jdbc:h2:mem:testdb";
        String user = "sa";
        String password = "";

        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            // Create table if not exists
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255), role VARCHAR(255))");
            stmt.execute("INSERT INTO users (id, username, email, role) VALUES (1, 'admin', 'admin@example.com', 'administrator')");
            stmt.execute("INSERT INTO users (id, username, email, role) VALUES (2, 'john', 'john@example.com', 'user')");
            stmt.execute("INSERT INTO users (id, username, email, role) VALUES (3, 'jane', 'jane@example.com', 'user')");

            // Vulnerability: Direct string concatenation in SQL query
            String sql = "SELECT * FROM users WHERE username = '" + username + "'";
            Statement queryStmt = conn.createStatement();
            ResultSet rs = queryStmt.executeQuery(sql);

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                results.add(Map.of(
                    "id", rs.getInt("id"),
                    "username", rs.getString("username"),
                    "email", rs.getString("email"),
                    "role", rs.getString("role")
                ));
            }

            return ResponseEntity.ok(Map.of(
                "query", sql,
                "results", results
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "query", username,
                "error", e.getMessage()
            ));
        }
    }

    /**
     * Another SQL injection endpoint with different parameter
     */
    @GetMapping("/user/lookup")
    public ResponseEntity<Map<String, Object>> lookupUser(@RequestParam(defaultValue = "1") String id) {
        String url = "jdbc:h2:mem:testdb";
        String user = "sa";
        String password = "";

        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(255), email VARCHAR(255), role VARCHAR(255))");
            stmt.execute("INSERT INTO users (id, username, email, role) VALUES (1, 'admin', 'admin@example.com', 'administrator')");
            stmt.execute("INSERT INTO users (id, username, email, role) VALUES (2, 'john', 'john@example.com', 'user')");

            // Vulnerability: Direct string concatenation
            String sql = "SELECT * FROM users WHERE id = " + id;
            Statement queryStmt = conn.createStatement();
            ResultSet rs = queryStmt.executeQuery(sql);

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                results.add(Map.of(
                    "id", rs.getInt("id"),
                    "username", rs.getString("username"),
                    "email", rs.getString("email"),
                    "role", rs.getString("role")
                ));
            }

            return ResponseEntity.ok(Map.of(
                "query", sql,
                "results", results
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "id", id,
                "error", e.getMessage()
            ));
        }
    }
}
