package com.snn.auth.infrastructure.security;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtils jwtUtils;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(JwtUtils jwtUtils, UserDetailsService userDetailsService) {
        this.jwtUtils = jwtUtils;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        Optional<String> jwtOpt = parseJwtFromRequest(request);

        jwtOpt.ifPresent(jwt -> authenticateUserFromJwt(jwt, request));

        logger.trace("Proceeding with filter chain for path: {}", request.getServletPath());
        filterChain.doFilter(request, response);
    }

    private Optional<String> parseJwtFromRequest(HttpServletRequest request) {
        try {
            return Optional.ofNullable(jwtUtils.parseJwt(request));
        } catch (Exception e) {
            logger.error("Error parsing JWT from request header: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private void authenticateUserFromJwt(String jwt, HttpServletRequest request) {
        try {
            if (jwtUtils.validateToken(jwt)) {
                String username = jwtUtils.getUsernameFromToken(jwt);
                logger.debug("JWT validated successfully for username: {}", username);

                if (isAuthenticationRequired()) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(authentication);
                    SecurityContextHolder.setContext(context);

                    logger.info("Successfully authenticated user '{}' via JWT and updated SecurityContext.", username);
                } else {
                    logger.trace("SecurityContext already holds non-anonymous authentication. Skipping JWT update.");
                }
            } else {
                logger.warn("JWT validation failed. Token will be ignored.");
            }
        } catch (Exception e) {
            logger.error("Error processing JWT and setting authentication: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }
    }

    private boolean isAuthenticationRequired() {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return existingAuth == null || existingAuth instanceof AnonymousAuthenticationToken;
    }
}
