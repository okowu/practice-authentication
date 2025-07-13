package com.okowu.app.authentication;

import com.okowu.app.authentication.schema.AuthenticationSuccess;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.utils.JwtUtils;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.hibernate.validator.constraints.Length;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

  private final SecurityProperties securityProperties;
  private final AuthenticationManager authenticationManager;

  @Override
  public AuthenticationSuccess login(
      @Email @NotBlank String email, @NotBlank @Length(min = 8) String password) {
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(email, password);
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    SecurityProperties.Jwt jwtProperties = securityProperties.jwt();
    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    String jwt = JwtUtils.createJwt(jwtProperties, userDetails);
    return new AuthenticationSuccess(jwt);
  }
}
