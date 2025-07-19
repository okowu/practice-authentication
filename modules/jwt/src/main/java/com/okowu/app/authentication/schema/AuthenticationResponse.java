package com.okowu.app.authentication.schema;


import static com.okowu.app.utils.JwtUtils.Token;

import java.util.Date;

public record AuthenticationResponse(String accessToken, String refreshToken, Date expirationDate) {

  public AuthenticationResponse(Token accessToken, Token refreshToken) {
    this(accessToken.value(), refreshToken.value(), accessToken.expirationDate());
  }
}
