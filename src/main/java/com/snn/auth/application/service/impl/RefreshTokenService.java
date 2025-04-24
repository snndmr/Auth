package com.snn.auth.application.service.impl;

import com.snn.auth.application.RefreshTokenRepository;
import com.snn.auth.application.UserRepository;
import com.snn.auth.application.exception.TokenRefreshException;
import com.snn.auth.domain.RefreshToken;
import com.snn.auth.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
                .orElseThrow(() -> {
                    logger.error("Cannot create refresh token. User not found for ID: {}", userId);
                    return new RuntimeException("Error: User not found for ID: " + userId);
                });

        Optional<RefreshToken> existingTokenOpt = refreshTokenRepository.findByUser(user);

        RefreshToken refreshToken;
        if (existingTokenOpt.isPresent()) {
            refreshToken = existingTokenOpt.get();
            refreshToken.setExpiresAt(Instant.now().plusMillis(refreshExpirationInMs));
            refreshToken.setToken(UUID.randomUUID().toString());
            logger.debug("Updating existing refresh token for user ID: {}", userId);
        } else {
            refreshToken = new RefreshToken();
            refreshToken.setUser(user);
            refreshToken.setExpiresAt(Instant.now().plusMillis(refreshExpirationInMs));
            refreshToken.setToken(UUID.randomUUID().toString());
            logger.debug("Creating new refresh token for user ID: {}", userId);
        }

        refreshToken = refreshTokenRepository.save(refreshToken);
        logger.info("Saved refresh token for user ID: {}. Token ID: {}", userId, refreshToken.getId());
        return refreshToken;
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(token);
            logger.warn("Refresh token ID {} for user ID {} has expired and was deleted.", token.getId(),
                        token.getUser().getId());
            throw new TokenRefreshException(token.getToken(),
                                            "Refresh token was expired. Please make a new signin request");
        }
        logger.trace("Refresh token ID {} is still valid.", token.getId());
        return token;
    }

    @Transactional
    public int deleteByUserId(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    logger.error("Cannot delete refresh token. User not found for ID: {}", userId);
                    return new RuntimeException("Error: User not found for ID: " + userId);
                });
        int deletedCount = refreshTokenRepository.deleteByUser(user);
        if (deletedCount > 0) {
            logger.info("Deleted {} refresh token(s) for user ID: {}", deletedCount, userId);
        } else {
            logger.debug("No refresh token found to delete for user ID: {}", userId);
        }
        return deletedCount;
    }
}
