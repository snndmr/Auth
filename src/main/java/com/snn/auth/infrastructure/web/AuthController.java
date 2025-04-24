package com.snn.auth.infrastructure.web;

import com.snn.auth.application.dto.*;
import com.snn.auth.application.service.AuthService;
import com.snn.auth.application.service.impl.RefreshTokenService;
import com.snn.auth.application.service.impl.TokenRefreshException;
import com.snn.auth.domain.User;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthService authService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        authService.registerUser(registerRequest);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.loginUser(loginRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof User user)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body(new MessageResponse("User not authenticated or principal type mismatch."));
        }

        Long userId = user.getId();
        String username = user.getUsername();

        try {
            int deletedCount = refreshTokenService.deleteByUserId(userId);
            logger.info("Logout successful for user: {}. Deleted {} refresh token(s).", username, deletedCount);
            SecurityContextHolder.clearContext();
            return ResponseEntity.ok(new MessageResponse("Logout successful!"));
        } catch (Exception e) {
            logger.error("Error during logout for user: {} (ID: {})", username, userId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(new MessageResponse("Logout failed due to an internal error."));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        try {
            RefreshTokenResponse response = authService.refreshToken(refreshTokenRequest);
            return ResponseEntity.ok(response);
        } catch (TokenRefreshException exception) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body(new MessageResponse("Error refreshing token: " + exception.getMessage()));
        } catch (Exception exception) {
            return ResponseEntity.badRequest().body(new MessageResponse(exception.getMessage()));
        }
    }
}
