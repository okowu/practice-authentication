package com.okowu.app.authentication.service;

import static com.okowu.app.authentication.service.TokenService.LoginToken;

import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.schema.LoginResponse;
import com.okowu.app.user.UserService;
import com.okowu.app.user.db.User;
import com.okowu.app.utils.SecurityUtils;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.hibernate.validator.constraints.Length;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

  private final UserService userService;
  private final TokenService tokenService;
  private final AuthenticationManager authenticationManager;

  @Override
  public LoginResponse login(
      @Email @NotBlank String email, @NotBlank @Length(min = 8) String password) {
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(email, password);
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    String role = SecurityUtils.getRole(userDetails.getAuthorities());
    LoginToken loginToken = tokenService.getLoginToken(userDetails.getUsername(), role);
    return new LoginResponse(loginToken);
  }

  @Override
  public LoginResponse refresh(@NotBlank String token) {
    RefreshToken refreshToken = tokenService.findRefreshToken(token);
    User user = userService.findByEmail(refreshToken.getSubject());
    LoginToken loginToken = tokenService.refreshToken(user, refreshToken);
    return new LoginResponse(loginToken);
  }

  @Override
  public void logout(String accessToken, String refreshToken) {
    RefreshToken refreshTokenEntity = tokenService.findRefreshToken(refreshToken);
    String subject = refreshTokenEntity.getSubject();
    tokenService.invalidateToken(subject, refreshTokenEntity.getToken());
    if (StringUtils.isNotBlank(accessToken)) {
      tokenService.invalidateToken(subject, accessToken);
    }
  }
}
