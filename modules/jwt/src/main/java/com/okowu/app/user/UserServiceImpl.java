package com.okowu.app.user;

import com.okowu.app.user.db.User;
import com.okowu.app.user.db.UserRepository;
import com.okowu.app.user.exception.UserException;
import com.okowu.app.user.schema.UserRegistrationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

  private final PasswordEncoder passwordEncoder;
  private final UserRepository userRepository;

  @Override
  public long registerUser(UserRegistrationRequest request) {
    if (userRepository.existsByEmail(request.email())) {
      throw new UserException("User with email " + request.email() + " already exists.");
    }

    String encodedPassword = passwordEncoder.encode(request.password());
    User user = new User();
    user.setEmail(request.email());
    user.setPassword(encodedPassword);
    user.setRole("ROLE_USER");
    return userRepository.save(user).getId();
  }
}
