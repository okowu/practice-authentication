package com.okowu.app.user.exception;

import com.okowu.app.AppException;
import org.springframework.http.HttpStatus;

public class UserException extends AppException {

  public static UserException userExists(String email) {
    UserException userException = new UserException();
    userException.setStatus(HttpStatus.CONFLICT);
    userException.setTitle("USER_ALREADY_EXISTS");
    userException.setMessage("User %s already exists.".formatted(email));
    return userException;
  }

  public static UserException userNotFound(String email) {
    UserException userException = new UserException();
    userException.setStatus(HttpStatus.NOT_FOUND);
    userException.setTitle("USER_NOT_FOUND");
    userException.setMessage("User with email %s not found".formatted(email));
    return userException;
  }
}
