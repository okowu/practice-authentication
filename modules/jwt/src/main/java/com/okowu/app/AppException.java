package com.okowu.app;

import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpStatus;

@Getter
@Setter
public class AppException extends RuntimeException {

  private HttpStatus status;
  private String title;
  private String message;
}
