package com.snn.auth.infrastructure.security;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

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
  protected void doFilterInternal(@NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response, @NonNull FilterChain filterChain)
      throws ServletException, IOException {
    try {
      String jwt = jwtUtils.parseJwt(request);

      if (jwt != null && jwtUtils.validateToken(jwt)) {
        String username = jwtUtils.getUsernameFromToken(jwt);

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
          UserDetails userDetails = userDetailsService.loadUserByUsername(username);

          UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
              userDetails, null, userDetails.getAuthorities());

          authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

          SecurityContextHolder.getContext().setAuthentication(authentication);
          logger.debug("Successfully authenticated user '{}' via JWT and set SecurityContext",
              username);
        } else {
          logger.trace("SecurityContext already contains Authentication for user '{}'",
              SecurityContextHolder.getContext().getAuthentication().getName());
        }
      } else {
        if (jwt == null && request.getHeader("Authorization") != null) {
          logger.trace("JWT was null or Authorization header was not 'Bearer' type for path: {}",
              request.getServletPath());
        } else if (jwt != null) {
          logger.trace("Invalid JWT received for path: {}", request.getServletPath());
        }
      }
    } catch (Exception exception) {
      logger.error(exception.getMessage(), exception);
    }

    filterChain.doFilter(request, response);
  }
}
