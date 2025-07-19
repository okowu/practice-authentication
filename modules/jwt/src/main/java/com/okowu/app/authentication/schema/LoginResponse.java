package com.okowu.app.authentication.schema;

import com.okowu.app.authentication.service.TokenService;
import java.util.Date;

public record LoginResponse(String accessToken, String refreshToken, Date expirationDate) {

  public LoginResponse(TokenService.LoginToken loginToken) {
    this(
        loginToken.accessToken().value(),
        loginToken.refreshToken().value(),
        loginToken.accessToken().expirationDate());
  }
}
