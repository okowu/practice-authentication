package com.okowu.app.configuration.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.okowu.app.authentication.service.TokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  private final ObjectMapper objectMapper = new ObjectMapper();
  private final TokenService tokenService;
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    String authorizationHeader = request.getHeader("Authorization");

    if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    String token = authorizationHeader.substring(7);

    try {
      Jwe<Claims> jwe = tokenService.validateToken(token);
      String subject = jwe.getPayload().getSubject();
      AppUserDetails userDetails = (AppUserDetails) userDetailsService.loadUserByUsername(subject);
      Authentication authentication =
          new AppAuthentication(
              userDetails.getEmail(),
              userDetails.getRealUsername(),
              userDetails.getPassword(),
              userDetails.getAuthorities());
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (ExpiredJwtException e) {
      sendServletErrorResponse(response, "EXPIRED_TOKEN", e);
      return;
    } catch (JwtException e) {
      sendServletErrorResponse(response, "INVALID_TOKEN", e);
      return;
    }

    filterChain.doFilter(request, response);
  }

  private void sendServletErrorResponse(HttpServletResponse response, String title, JwtException e)
      throws IOException {
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    Map<String, Object> errors = new HashMap<>();
    errors.put("status", HttpServletResponse.SC_FORBIDDEN);
    errors.put("title", title);
    errors.put("message", e.getMessage());
    response.getWriter().write(objectMapper.writeValueAsString(errors));
  }
}
