package com.example.shannontarget.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
public class XssController {

    // In-memory storage for comments (no database)
    private final List<Map<String, String>> comments = new java.util.concurrent.CopyOnWriteArrayList<>();

    /**
     * XSS vulnerability - user input is reflected without sanitization
     * Vulnerability: No output encoding, allows script injection
     */
    @PostMapping("/comment")
    public ResponseEntity<Map<String, Object>> addComment(@RequestParam String content) {
        // Vulnerability: No input sanitization or output encoding
        comments.add(Map.of(
            "content", content,
            "timestamp", java.time.Instant.now().toString()
        ));

        return ResponseEntity.ok(Map.of(
            "success", true,
            "message", "Comment added",
            "total_comments", comments.size()
        ));
    }

    /**
     * XSS vulnerability - reflects user input directly in response
     */
    @GetMapping("/comment")
    public ResponseEntity<Map<String, Object>> getComments(@RequestParam(required = false) String filter) {
        List<Map<String, String>> filteredComments = new ArrayList<>();

        for (Map<String, String> comment : comments) {
            if (filter == null || filter.isEmpty() ||
                comment.get("content").toLowerCase().contains(filter.toLowerCase())) {
                // Vulnerability: No output encoding when reflecting filter parameter
                filteredComments.add(comment);
            }
        }

        return ResponseEntity.ok(Map.of(
            "filter", filter != null ? filter : "",
            "comments", filteredComments
        ));
    }

    /**
     * XSS vulnerability - search parameter reflected in HTML without encoding
     */
    @GetMapping("/search")
    public ResponseEntity<Map<String, Object>> search(@RequestParam String q) {
        // Vulnerability: Query parameter reflected without encoding
        return ResponseEntity.ok(Map.of(
            "query", q,
            "results", List.of("Result 1 for " + q, "Result 2 for " + q)
        ));
    }

    /**
     * XSS in user profile - name field rendered without encoding
     */
    @PostMapping("/profile")
    public ResponseEntity<Map<String, Object>> updateProfile(
            @RequestParam String name,
            @RequestParam String bio) {
        // Vulnerability: No input validation or output encoding
        return ResponseEntity.ok(Map.of(
            "name", name,
            "bio", bio,
            "message", "Profile updated"
        ));
    }
}
