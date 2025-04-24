package com.snn.auth.application.service.impl;

import com.snn.auth.application.RoleRepository;
import com.snn.auth.application.UserRepository;
import com.snn.auth.application.dto.LoginRequest;
import com.snn.auth.application.dto.LoginResponse;
import com.snn.auth.application.dto.RegisterRequest;
import com.snn.auth.application.service.AuthService;
import com.snn.auth.domain.Role;
import com.snn.auth.domain.User;
import com.snn.auth.infrastructure.security.JwtUtils;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Set;

@Service
public class AuthServiceImpl implements AuthService {

    public static final String ROLE_USER = "ROLE_USER";
    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @Autowired
    public AuthServiceImpl(
            UserRepository userRepository,
            RoleRepository roleRepository,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            JwtUtils jwUtils) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtUtils = jwUtils;
    }

    @Override
    @Transactional
    public void registerUser(RegisterRequest registerRequest) {
        logger.info("Attempting registration for user: {}", registerRequest.getUsername());

        if (userRepository.existsUserByUsername(registerRequest.getUsername())) {
            logger.warn("User {} already exists", registerRequest.getUsername());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username already exists");
        }

        if (userRepository.existsUserByEmail(registerRequest.getEmail())) {
            logger.warn("Email {} already exists", registerRequest.getEmail());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already exists");
        }

        User user = new User(registerRequest.getUsername(), registerRequest.getEmail(),
                             passwordEncoder.encode(registerRequest.getPassword()));

        Role userRole = roleRepository.findByName(ROLE_USER)
                .orElseThrow(() -> {
                    logger.error("Role {} not found", ROLE_USER);
                    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found");
                });

        user.setRoles(Set.of(userRole));

        userRepository.save(user);
        logger.info("User {} successfully registered", registerRequest.getUsername());
    }

    @Override
    public LoginResponse loginUser(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);

        User userDetails = (User) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        logger.info("User {} successfully logged in", userDetails.getUsername());

        return new LoginResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles);
    }
}
