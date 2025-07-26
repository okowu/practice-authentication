package com.okowu.app.configuration.security;

import com.okowu.app.user.db.User;
import java.util.Collection;
import java.util.List;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@RequiredArgsConstructor
public class AppUserDetails implements UserDetails {

  @Getter private final String email;
  private final String username;
  private final String password;
  private final String role;

  public AppUserDetails(User user) {
    this(user.getEmail(), user.getUsername(), user.getPassword(), user.getRole());
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority(role));
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public String getUsername() {
    return email;
  }

  public String getRealUsername() {
    return username;
  }
}
