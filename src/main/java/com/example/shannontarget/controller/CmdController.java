package com.example.shannontarget.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

@RestController
public class CmdController {

    /**
     * Command injection vulnerability - user input directly concatenated with OS command
     * Vulnerability: No input validation, allows shell command injection
     */
    @GetMapping("/ping")
    public ResponseEntity<Map<String, Object>> ping(@RequestParam(defaultValue = "127.0.0.1") String host) {
        try {
            // Vulnerability: Direct string concatenation in command
            // Attacker can inject: 127.0.0.1; cat /etc/passwd
            String command = "ping -n 2 " + host;

            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();

            return ResponseEntity.ok(Map.of(
                "host", host,
                "command", command,
                "output", output.toString(),
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "host", host,
                "error", e.getMessage()
            ));
        }
    }

    /**
     * Another command injection endpoint - traceroute
     */
    @GetMapping("/traceroute")
    public ResponseEntity<Map<String, Object>> traceroute(@RequestParam String target) {
        try {
            // Vulnerability: No input validation
            String command = "tracert -d -w 100 " + target;

            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();

            return ResponseEntity.ok(Map.of(
                "target", target,
                "output", output.toString(),
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "target", target,
                "error", e.getMessage()
            ));
        }
    }

    /**
     * Command injection with different injection point
     */
    @GetMapping("/nslookup")
    public ResponseEntity<Map<String, Object>> nslookup(@RequestParam String domain) {
        try {
            // Vulnerability: Direct concatenation
            String command = "nslookup " + domain;

            ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", command);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            int exitCode = process.waitFor();

            return ResponseEntity.ok(Map.of(
                "domain", domain,
                "output", output.toString(),
                "exitCode", exitCode
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "domain", domain,
                "error", e.getMessage()
            ));
        }
    }
}
