package com.okowu.app.user.exception;

public class UserException extends RuntimeException {

  public UserException(String message) {
    super(message);
  }

  public static UserException userAlreadyExists(String email) {
    return new UserException("User with email " + email + " already exists.");
  }
}
