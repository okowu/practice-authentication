package com.okowu.app.authentication.service;

import static com.okowu.app.utils.JwtUtils.Token;

import com.okowu.app.authentication.AuthenticationException;
import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.db.RefreshTokenRepository;
import com.okowu.app.authentication.schema.AuthenticationResponse;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.user.UserService;
import com.okowu.app.user.db.User;
import com.okowu.app.utils.JwtUtils;
import com.okowu.app.utils.SecurityUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import java.util.Optional;
import java.util.function.Predicate;
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

  private final UserService userService;
  private final SecurityProperties securityProperties;
  private final RefreshTokenRepository refreshTokenRepository;
  private final AuthenticationManager authenticationManager;

  @Override
  public AuthenticationResponse login(
      @Email @NotBlank String email, @NotBlank @Length(min = 8) String password) {
    UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(email, password);
    Authentication authentication = authenticationManager.authenticate(authenticationToken);
    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    String role = SecurityUtils.getRole(userDetails.getAuthorities());
    return authenticationResponse(userDetails.getUsername(), role);
  }

  @Override
  public AuthenticationResponse refresh(@NotBlank String token) {
    String secretKey = securityProperties.jwt().secretKey();
    Jwe<Claims> jwe = JwtUtils.parseToken(token, secretKey);
    String email = jwe.getPayload().getSubject();

    User user = userService.findByEmail(email);

    Optional<RefreshToken> optionalRefreshToken = findRefreshToken(email, token);

    if (optionalRefreshToken.isEmpty()) {
      throw AuthenticationException.refreshTokenNotFound();
    }

    RefreshToken refreshToken = optionalRefreshToken.get();
    refreshToken.setUsed(true);
    refreshTokenRepository.save(refreshToken);

    return authenticationResponse(user.getEmail(), user.getRole());
  }

  private AuthenticationResponse authenticationResponse(String email, String role) {
    String secretKey = securityProperties.jwt().secretKey();
    long expirationMillis = securityProperties.jwt().expirationMillis();
    long refreshExpirationMillis = securityProperties.jwt().refreshExpirationMillis();
    Token accessToken =
        JwtUtils.generateAccessToken(email, role, expirationMillis, secretKey);
    Token refreshToken =
        JwtUtils.generateRefreshToken(email, refreshExpirationMillis, secretKey);
    saveRefreshToken(email, refreshToken);
    return new AuthenticationResponse(accessToken, refreshToken);
  }

  private Optional<RefreshToken> findRefreshToken(String email, String token) {
    return refreshTokenRepository.findBySubject(email).stream()
        .filter(Predicate.not(RefreshToken::isUsed))
        .filter(refreshToken -> refreshToken.getToken().equals(token))
        .findFirst();
  }

  private void saveRefreshToken(String email, Token refreshTokenResult) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setSubject(email);
    refreshToken.setToken(refreshTokenResult.value());
    refreshToken.setExpiresAt(refreshTokenResult.expirationDate().toInstant());
    refreshTokenRepository.save(refreshToken);
  }
}
