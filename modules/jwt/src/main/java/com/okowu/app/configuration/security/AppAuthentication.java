package com.okowu.app.configuration.security;

import java.util.Collection;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class AppAuthentication extends AbstractAuthenticationToken {

  private final String email;
  @Getter private final String username;
  private final String password;

  /**
   * Creates a token with the supplied array of authorities.
   *
   * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal represented
   *     by this authentication object.
   */
  public AppAuthentication(
      String email,
      String username,
      String password,
      Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    this.email = email;
    this.username = username;
    this.password = password;
  }

  @Override
  public Object getCredentials() {
    return password;
  }

  @Override
  public Object getPrincipal() {
    return email;
  }

  @Override
  public boolean isAuthenticated() {
    return true;
  }
}
