package com.snn.auth.application.service;

import com.snn.auth.application.dto.LoginRequest;
import com.snn.auth.application.dto.LoginResponse;
import com.snn.auth.application.dto.RegisterRequest;

public interface AuthService {

    void registerUser(RegisterRequest registerRequest);

    LoginResponse loginUser(LoginRequest loginRequest);
}
