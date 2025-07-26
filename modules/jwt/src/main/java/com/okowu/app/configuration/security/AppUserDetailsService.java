package com.okowu.app.configuration.security;

import com.okowu.app.user.db.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

  private final UserRepository userRepository;

  @Override
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

    return userRepository
        .findByEmail(email)
        .map(AppUserDetails::new)
        .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
  }
}
