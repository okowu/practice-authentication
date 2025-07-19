package com.okowu.app.authentication.service;

import com.okowu.app.authentication.schema.LoginResponse;

public interface AuthenticationService {

  LoginResponse login(String email, String password);

  LoginResponse refresh(String refreshToken);

  void logout(String accessToken, String refreshToken);
}
