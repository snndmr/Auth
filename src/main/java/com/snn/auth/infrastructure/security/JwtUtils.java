package com.snn.auth.infrastructure.security;

import com.snn.auth.domain.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.jwtExpirationInMs}")
    private int jwtExpirationInMs;

    private SecretKey cachedKey;

    private SecretKey getKey() {
        if (cachedKey == null) {
            byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
            this.cachedKey = Keys.hmacShaKeyFor(keyBytes);
        }

        return this.cachedKey;
    }

    public String generateJwtToken(Authentication authentication) {
        User userPrincipal = (User) authentication.getPrincipal();

        return Jwts.builder()
                   .subject(userPrincipal.getUsername())
                   .issuedAt(new Date())
                   .expiration(new Date((new Date()).getTime() + jwtExpirationInMs))
                   .signWith(getKey(), Jwts.SIG.HS512)
                   .compact();
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parser().verifyWith(getKey())
                .build().parseSignedClaims(token).getPayload().getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().verifyWith(getKey())
                    .build().parseSignedClaims(token);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty or invalid: {}", e.getMessage());
        } catch (JwtException e) {
            logger.error("JWT validation error: {}", e.getMessage());
        }

        return false;
    }

    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        logger.trace("Could not find Bearer string in Authorization header, will ignore the header.");
        return null;
    }
}
