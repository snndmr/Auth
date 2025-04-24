package com.snn.auth.application.service;

import com.snn.auth.application.dto.*;

public interface AuthService {

    void registerUser(RegisterRequest registerRequest);

    LoginResponse loginUser(LoginRequest loginRequest);

    RefreshTokenResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
