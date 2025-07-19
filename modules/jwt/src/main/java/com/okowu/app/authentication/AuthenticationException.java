package com.okowu.app.authentication;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AuthenticationException extends RuntimeException {

  private HttpStatus status;
  private String title;
  private String message;

  public AuthenticationException() {
    super();
  }

  public static AuthenticationException refreshTokenNotFound() {
    AuthenticationException authenticationException = new AuthenticationException();
    authenticationException.status = HttpStatus.FORBIDDEN;
    authenticationException.title = "REFRESH_TOKEN_NOT_FOUND";
    authenticationException.message = "The refresh token is not associated with any user";
    return authenticationException;
  }

  public static AuthenticationException invalidToken() {
    AuthenticationException authenticationException = new AuthenticationException();
    authenticationException.status = HttpStatus.FORBIDDEN;
    authenticationException.title = "INVALID_TOKEN";
    authenticationException.message = "The given token is invalid";
    return authenticationException;
  }
}
