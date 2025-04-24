package com.snn.auth.infrastructure.web; // Use your actual package name

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Test Authorization", description = "Endpoints to test role-based access")
@SecurityRequirement(name = "bearerAuth")
public class TestController {

    @Operation(summary = "Access public test endpoint (requires authentication)")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Successful access"),
                           @ApiResponse(responseCode = "401", description = "Authentication required")})
    @GetMapping("/hello")
    public ResponseEntity<String> sayHello() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "Hello " + authentication.getName() + "! This endpoint requires authentication.";
        return ResponseEntity.ok(message);
    }

    @Operation(summary = "Access endpoint restricted to ROLE_USER")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Successful access"),
                           @ApiResponse(responseCode = "401", description = "Authentication required"),
                           @ApiResponse(responseCode = "403", description = "Forbidden (User lacks ROLE_USER)")})
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> userAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "User Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }

    @Operation(summary = "Access endpoint restricted to ROLE_ADMIN")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Successful access"),
                           @ApiResponse(responseCode = "401", description = "Authentication required"),
                           @ApiResponse(responseCode = "403", description = "Forbidden (User lacks ROLE_ADMIN)")})
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "Admin Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }

    @Operation(summary = "Access endpoint restricted to ROLE_USER or ROLE_ADMIN")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Successful access"),
                           @ApiResponse(responseCode = "401", description = "Authentication required"),
                           @ApiResponse(responseCode = "403", description = "Forbidden (User lacks required roles)")})
    @GetMapping("/all-roles")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<String> allRolesAccess() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String message = "All Roles Content: Accessed by " + authentication.getName() + " with roles " + authentication.getAuthorities();
        return ResponseEntity.ok(message);
    }
}