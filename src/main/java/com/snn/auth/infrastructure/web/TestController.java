package com.snn.auth.infrastructure.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
@CrossOrigin(origins = "*", maxAge = 3600)
public class TestController {

    @GetMapping("/hello")
    public ResponseEntity<String> sayHello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "Hello " + authentication.getName();
        return ResponseEntity.ok(message);
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> userAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "User Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "Admin Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }

    @GetMapping("/all-roles")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<String> allRolesAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "All Roles Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }
}
