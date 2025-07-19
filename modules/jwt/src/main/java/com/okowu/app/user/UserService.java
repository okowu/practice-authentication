package com.okowu.app.user;

import com.okowu.app.user.db.User;
import com.okowu.app.user.schema.UserRegistrationRequest;

public interface UserService {

  long registerUser(UserRegistrationRequest request);

  User findByEmail(String email);
}
