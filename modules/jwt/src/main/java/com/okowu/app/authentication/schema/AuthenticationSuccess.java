package com.okowu.app.authentication.schema;

import com.okowu.app.authentication.service.TokenService;
import java.util.Date;

public record AuthenticationSuccess(
    String username, String email, String accessToken, String refreshToken, Date expirationDate) {

  public AuthenticationSuccess(String username, String email, TokenService.UserToken userToken) {
    this(
        username,
        email,
        userToken.accessToken().value(),
        userToken.refreshToken().value(),
        userToken.accessToken().expirationDate());
  }
}
