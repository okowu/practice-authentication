package com.okowu.app.authentication;

import com.okowu.app.AppException;
import org.springframework.http.HttpStatus;

public class AuthenticationException extends AppException {

  public static AuthenticationException refreshTokenNotFound() {
    AuthenticationException authenticationException = new AuthenticationException();
    authenticationException.setStatus(HttpStatus.FORBIDDEN);
    authenticationException.setTitle("REFRESH_TOKEN_NOT_FOUND");
    authenticationException.setMessage("The refresh token is not associated with any user");
    return authenticationException;
  }

  public static AuthenticationException invalidToken() {
    AuthenticationException authenticationException = new AuthenticationException();
    authenticationException.setStatus(HttpStatus.FORBIDDEN);
    authenticationException.setTitle("INVALID_TOKEN");
    authenticationException.setMessage("The given token is invalid");
    return authenticationException;
  }
}
