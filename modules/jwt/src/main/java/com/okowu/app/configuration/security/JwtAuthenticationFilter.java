package com.okowu.app.configuration.security;

import com.okowu.app.authentication.AuthenticationException;
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
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

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
      UserDetails userDetails = userDetailsService.loadUserByUsername(subject);
      Authentication authentication =
          new UsernamePasswordAuthenticationToken(
              userDetails.getUsername(), userDetails.getPassword(), userDetails.getAuthorities());
      SecurityContextHolder.getContext().setAuthentication(authentication);
    } catch (ExpiredJwtException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Expired JWT value");
      return;
    } catch (JwtException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT value");
      return;
    } catch (AuthenticationException e) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, e.getMessage());
      return;
    }

    filterChain.doFilter(request, response);
  }
}
