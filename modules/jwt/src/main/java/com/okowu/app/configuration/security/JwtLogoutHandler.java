package com.okowu.app.configuration.security;

import com.okowu.app.authentication.service.AuthenticationService;
import com.okowu.app.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@RequiredArgsConstructor
public class JwtLogoutHandler implements LogoutHandler {

  private final AuthenticationService authenticationService;

  @Override
  public void logout(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    String accessToken = SecurityUtils.extractAccessToken(request);
    authenticationService.logout(accessToken);
  }
}
