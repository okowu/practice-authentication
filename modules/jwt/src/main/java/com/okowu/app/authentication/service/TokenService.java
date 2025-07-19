package com.okowu.app.authentication.service;

import static com.okowu.app.utils.JwtUtils.Token;

import com.okowu.app.authentication.AuthenticationException;
import com.okowu.app.authentication.db.InvalidatedToken;
import com.okowu.app.authentication.db.InvalidatedTokenRepository;
import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.db.RefreshTokenRepository;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.user.db.User;
import com.okowu.app.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {

  private final SecurityProperties securityProperties;
  private final RefreshTokenRepository refreshTokenRepository;
  private final InvalidatedTokenRepository invalidatedTokenRepository;

  public record LoginToken(Token accessToken, Token refreshToken) {}

  public LoginToken getLoginToken(String email, String role) {
    String secretKey = securityProperties.jwt().secretKey();
    long expirationMillis = securityProperties.jwt().expirationMillis();
    long refreshExpirationMillis = securityProperties.jwt().refreshExpirationMillis();

    Token accessToken = JwtUtils.getAccessToken(email, role, securityProperties);
    Token refreshToken = JwtUtils.getRefreshToken(email, securityProperties);

    RefreshToken refreshTokenToSave = new RefreshToken();
    refreshTokenToSave.setSubject(email);
    refreshTokenToSave.setToken(refreshToken.value());
    refreshTokenToSave.setExpiresAt(refreshToken.expirationDate().toInstant());
    refreshTokenRepository.save(refreshTokenToSave);

    return new LoginToken(accessToken, refreshToken);
  }

  public RefreshToken findRefreshToken(String token) {
    String secretKey = securityProperties.jwt().secretKey();
    Jwe<Claims> jwt = JwtUtils.parseToken(token, secretKey);
    String subject = jwt.getPayload().getSubject();

    assertTokenNotInvalidated(subject, token);

    return refreshTokenRepository.findBySubject(subject).stream()
        .filter(Predicate.not(RefreshToken::isUsed))
        .filter(refreshToken -> refreshToken.equalsToken(token))
        .findFirst()
        .orElseThrow(AuthenticationException::refreshTokenNotFound);
  }

  public LoginToken refreshToken(User user, RefreshToken refreshToken) {
    assertTokenNotInvalidated(user.getEmail(), refreshToken.getToken());

    refreshToken.setUsed(true);
    refreshTokenRepository.save(refreshToken);
    invalidateToken(refreshToken.getSubject(), refreshToken.getToken());

    return getLoginToken(user.getEmail(), user.getRole());
  }

  public Jwe<Claims> validateToken(String token) {
    String secretKey = securityProperties.jwt().secretKey();
    Jwe<Claims> jwt = JwtUtils.parseToken(token, secretKey);
    assertTokenNotInvalidated(jwt.getPayload().getSubject(), token);
    return jwt;
  }

  public void invalidateToken(String subject, String token) {
    InvalidatedToken invalidatedToken = new InvalidatedToken();
    invalidatedToken.setSubject(subject);
    invalidatedToken.setToken(token);
    invalidatedTokenRepository.save(invalidatedToken);
  }

  private void assertTokenNotInvalidated(String subject, String token) {
    invalidatedTokenRepository
        .findBySubjectAndToken(subject, token)
        .ifPresent(
            _ -> {
              throw AuthenticationException.invalidToken();
            });
  }
}
