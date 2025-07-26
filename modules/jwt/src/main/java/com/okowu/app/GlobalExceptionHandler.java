package com.okowu.app;

import com.okowu.app.authentication.AuthenticationException;
import com.okowu.app.user.exception.UserException;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<Map<String, String>> handleValidationErrors(
      MethodArgumentNotValidException ex) {
    Map<String, String> errors = new HashMap<>();
    ex.getBindingResult()
        .getFieldErrors()
        .forEach(error -> errors.put(error.getField(), error.getDefaultMessage()));
    return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
  }

  @ExceptionHandler(UserException.class)
  public ResponseEntity<Map<String, String>> handleUserException(UserException ex) {
    return handleAppException(ex);
  }

  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<Map<String, String>> handleAuthenticationException(
      AuthenticationException ex) {
    return handleAppException(ex);
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<Map<String, String>> handleBadCredentialsException(
      BadCredentialsException ex) {
    return handleException(HttpStatus.UNAUTHORIZED, "BAD_CREDENTIALS", "Invalid email or password");
  }

  private ResponseEntity<Map<String, String>> handleAppException(AppException ex) {
    return handleException(ex.getStatus(), ex.getTitle(), ex.getMessage());
  }

  private ResponseEntity<Map<String, String>> handleException(
      HttpStatus status, String title, String message) {
    Map<String, String> errors = new HashMap<>();
    errors.put("status", status.toString());
    errors.put("title", title);
    errors.put("message", message);
    return new ResponseEntity<>(errors, status);
  }
}
