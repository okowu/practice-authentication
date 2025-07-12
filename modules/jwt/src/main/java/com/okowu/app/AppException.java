package com.okowu.app;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class AppException extends RuntimeException {

  private String code;
  private String title;
  private String detail;
}
