package com.okowu.app.user.exception;

import com.okowu.app.AppException;

public class UserException extends AppException {

  public static UserException USER_NOT_FOUND =
      new UserException("404", "User Not Found", "The requested user does not exist.");
  public static UserException USER_ALREADY_EXISTS =
      new UserException(
          "409", "User Already Exists", "A user with the provided email already exists.");

  public UserException(String code, String title, String detail) {
    super(code, title, detail);
  }
}
