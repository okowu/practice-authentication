package com.okowu.app.user;

import com.okowu.app.user.db.User;
import com.okowu.app.user.db.UserRepository;
import com.okowu.app.user.exception.UserException;
import com.okowu.app.user.schema.UserRegistrationRequest;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
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
      throw UserException.USER_ALREADY_EXISTS;
    }

    String encodedPassword = passwordEncoder.encode(request.password());
    User user = new User();
    user.setEmail(request.email());
    user.setPassword(encodedPassword);
    user.setRole("USER");
    return userRepository.save(user).getId();
  }

  @Override
  public User findByEmail(@Email @NotBlank String email) {
    return userRepository.findByEmail(email).orElseThrow(() -> UserException.userNotFound(email));
  }
}
