package com.okowu.app.authentication.service;

import static com.okowu.app.authentication.service.TokenService.UserToken;

import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.schema.AuthenticationSuccess;
import com.okowu.app.configuration.security.AppUserDetails;
import com.okowu.app.user.UserService;
import com.okowu.app.user.db.User;
import com.okowu.app.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwe;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

  private final UserService userService;
  private final TokenService tokenService;
  private final AuthenticationManager authenticationManager;

  @Override
  public AuthenticationSuccess login(String email, String password) {
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(email, password);
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();
    String username = userDetails.getRealUsername();
    String role = SecurityUtils.getRole(userDetails.getAuthorities());
    UserToken userToken = tokenService.createUserToken(email, role);
    return new AuthenticationSuccess(email, username, userToken);
  }

  @Override
  public AuthenticationSuccess refresh(String token) {
    Jwe<Claims> claims = tokenService.validateToken(token);
    User user = userService.findByEmail(claims.getPayload().getSubject());
    UserToken userToken = tokenService.refreshUserToken(user.getEmail(), user.getRole(), token);
    return new AuthenticationSuccess(user.getEmail(), user.getUsername(), userToken);
  }

  @Override
  public void logout(String accessToken) {
    Claims claims = parseToken(accessToken);
    List<RefreshToken> refreshTokens = tokenService.findRefreshTokens(claims.getSubject());

    for (RefreshToken refreshToken : refreshTokens) {
      tokenService.invalidateToken(claims.getSubject(), refreshToken.getToken());
    }

    if (StringUtils.isNotBlank(accessToken)) {
      tokenService.invalidateToken(claims.getSubject(), accessToken);
    }
  }

  private Claims parseToken(String token) {
    try {
      Jwe<Claims> jwe = tokenService.validateToken(token);
      return jwe.getPayload();
    } catch (ExpiredJwtException e) {
      return e.getClaims();
    }
  }
}
