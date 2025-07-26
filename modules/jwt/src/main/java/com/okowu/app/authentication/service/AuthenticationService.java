package com.okowu.app.authentication.service;

import com.okowu.app.authentication.schema.AuthenticationSuccess;

public interface AuthenticationService {

  AuthenticationSuccess login(String email, String password);

  AuthenticationSuccess refresh(String refreshToken);

  void logout(String accessToken);
}
