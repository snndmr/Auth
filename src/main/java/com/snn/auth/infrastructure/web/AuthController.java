package com.snn.auth.infrastructure.web;

import com.snn.auth.application.dto.*;
import com.snn.auth.application.exception.TokenRefreshException;
import com.snn.auth.application.service.AuthService;
import com.snn.auth.application.service.impl.RefreshTokenService;
import com.snn.auth.domain.User;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
@Tag(name = "Authentication", description = "Endpoints for user authentication and session management")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public AuthController(AuthService authService, RefreshTokenService refreshTokenService) {
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    @Operation(summary = "Register a new user")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "User registered successfully",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = MessageResponse.class))),
                           @ApiResponse(responseCode = "400",
                                        description = "Invalid input (e.g., username/email taken, validation error)",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = MessageResponse.class)))})
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        authService.registerUser(registerRequest);
        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Operation(summary = "Authenticate user and obtain tokens")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Login successful",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = LoginResponse.class))),
                           @ApiResponse(responseCode = "401", description = "Invalid credentials",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = MessageResponse.class)))})
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        LoginResponse response = authService.loginUser(loginRequest);
        return ResponseEntity.ok(response);
    }

    @Operation(summary = "Log out the current user", description = "Invalidates the user's refresh token.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Logout successful",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = MessageResponse.class))),
                           @ApiResponse(responseCode = "401", description = "User not authenticated"),
                           @ApiResponse(responseCode = "500", description = "Internal server error during logout")})
    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logoutUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!(authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof User currentUser)) {
            logger.warn("Logout attempt by unauthenticated or unrecognized principal.");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body(new MessageResponse("User is not properly authenticated."));
        }

        Long userId = currentUser.getId();
        String username = currentUser.getUsername();
        logger.info("Processing logout request for user: {} (ID: {})", username, userId);

        try {
            refreshTokenService.deleteByUserId(userId);
            SecurityContextHolder.clearContext();
            return ResponseEntity.ok(new MessageResponse("Logout successful!"));
        } catch (Exception e) {
            logger.error("Error during logout for user: {} (ID: {})", username, userId, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(new MessageResponse("Logout failed due to an internal error."));
        }
    }

    @Operation(summary = "Refresh access token", description = "Obtain a new access token using a valid refresh token.")
    @ApiResponses(value = {@ApiResponse(responseCode = "200", description = "Token refresh successful",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(
                                                                   implementation = RefreshTokenResponse.class))),
                           @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token",
                                        content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                                           schema = @Schema(implementation = MessageResponse.class)))})
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        try {
            RefreshTokenResponse response = authService.refreshToken(request);
            return ResponseEntity.ok(response);
        } catch (TokenRefreshException ex) {
            logger.warn("Token refresh failed: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                 .body(new MessageResponse("Token refresh failed: " + ex.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during token refresh.", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                 .body(new MessageResponse("An internal error occurred during token refresh."));
        }
    }
}
