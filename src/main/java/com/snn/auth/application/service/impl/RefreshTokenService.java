package com.snn.auth.application.service.impl;

import com.snn.auth.application.RefreshTokenRepository;
import com.snn.auth.application.UserRepository;
import com.snn.auth.domain.RefreshToken;
import com.snn.auth.domain.User;
import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private static final Logger logger = LoggerFactory.getLogger(RefreshTokenService.class);
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    @Value("${app.jwt.refreshExpirationInMs}")
    private Long refreshExpirationInMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createOrUpdateRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Error: user not found for ID: " + userId));

        refreshTokenRepository.deleteByUser(user);
        logger.debug("Deleting existing refresh token for user: {}", user);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiresAt(Instant.now().plusMillis(refreshExpirationInMs));
        refreshToken.setToken(UUID.randomUUID().toString());

        refreshTokenRepository.save(refreshToken);
        logger.info("Created new refresh token for user ID: {}. Token ID: {}", userId, refreshToken.getId());

        return refreshToken;
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            logger.warn("Refresh token expired. Token: {}", token);
            throw new TokenRefreshException(token.getToken(),
                                            "Refresh token was expired. Please make a new signin request");
        }

        logger.trace("Refresh token is still valid. Token: {}", token);
        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Error: user not found for ID: " + userId));
        int deletedCount = refreshTokenRepository.deleteByUser(user);
        logger.info("Deleted {} refresh token(s) for user ID: {}", deletedCount, userId);
        return deletedCount;
    }
}

