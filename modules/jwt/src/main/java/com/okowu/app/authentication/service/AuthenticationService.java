package com.okowu.app.authentication.service;

import com.okowu.app.authentication.schema.AuthenticationResponse;

public interface AuthenticationService {

  AuthenticationResponse login(String email, String password);

  AuthenticationResponse refresh(String refreshToken);
}
