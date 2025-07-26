package com.okowu.app;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public abstract class AppException extends RuntimeException {

  protected HttpStatus status;
  protected String title;
  protected String message;

  protected AppException() {}

  protected AppException(Throwable e) {
    super(e);
  }
}
