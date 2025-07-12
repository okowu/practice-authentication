package com.okowu.app.authentication;

import com.okowu.app.authentication.schema.AuthenticationSuccess;

public interface AuthenticationService {

  AuthenticationSuccess login(String email, String password);
}
