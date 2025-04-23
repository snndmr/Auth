package com.snn.auth.infrastructure.web;

import com.snn.auth.application.dto.LoginRequest;
import com.snn.auth.application.dto.MessageResponse;
import com.snn.auth.application.dto.RegisterRequest;
import com.snn.auth.application.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
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
}
