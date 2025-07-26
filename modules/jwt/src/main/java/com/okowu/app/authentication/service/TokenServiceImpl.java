package com.okowu.app.authentication.service;

import com.okowu.app.authentication.AuthenticationException;
import com.okowu.app.authentication.db.InvalidatedToken;
import com.okowu.app.authentication.db.InvalidatedTokenRepository;
import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.db.RefreshTokenRepository;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

  private final SecurityProperties securityProperties;
  private final RefreshTokenRepository refreshTokenRepository;
  private final InvalidatedTokenRepository invalidatedTokenRepository;

  @Override
  public UserToken createUserToken(String email, String role) {
    String secretKey = securityProperties.jwt().secretKey();
    long expirationMillis = securityProperties.jwt().expirationMillis();
    long refreshExpirationMillis = securityProperties.jwt().refreshExpirationMillis();

    JwtUtils.Token accessToken = createAccessToken(email, role);
    JwtUtils.Token refreshToken = createRefreshToken(email);

    RefreshToken refreshTokenToSave = new RefreshToken();
    refreshTokenToSave.setSubject(email);
    refreshTokenToSave.setToken(refreshToken.value());
    refreshTokenToSave.setExpiresAt(refreshToken.expirationDate().toInstant());
    refreshTokenRepository.save(refreshTokenToSave);

    return new UserToken(accessToken, refreshToken);
  }

  @Override
  public UserToken refreshUserToken(String email, String role, String token) {
    Optional<RefreshToken> optional = refreshTokenRepository.findByToken(token);

    if (optional.isEmpty()) {
      throw AuthenticationException.invalidToken("Refresh token not found");
    }

    RefreshToken refreshToken = optional.get();

    if (refreshToken.isUsed()) {
      throw AuthenticationException.invalidToken("Refresh token already used");
    }

    assertTokenNotInvalidated(email, refreshToken.getToken());
    refreshToken.setUsed(true);
    refreshTokenRepository.save(refreshToken);
    invalidateToken(refreshToken.getSubject(), refreshToken.getToken());

    return createUserToken(email, role);
  }

  @Override
  public Jwe<Claims> validateToken(String token) {
    String secretKey = securityProperties.jwt().secretKey();
    Jwe<Claims> jwt = JwtUtils.parseToken(token, secretKey);
    assertTokenNotInvalidated(jwt.getPayload().getSubject(), token);
    return jwt;
  }

  @Override
  public void invalidateToken(String email, String token) {
    InvalidatedToken invalidatedToken = new InvalidatedToken();
    invalidatedToken.setSubject(email);
    invalidatedToken.setToken(token);
    invalidatedTokenRepository.save(invalidatedToken);
  }

  @Override
  public List<RefreshToken> findRefreshTokens(String email) {
    return refreshTokenRepository.findBySubject(email);
  }

  @Override
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

  private JwtUtils.Token createAccessToken(String email, String role) {
    SecurityProperties.Jwt jwt = securityProperties.jwt();
    return JwtUtils.createAccessToken(email, "", role, jwt.expirationMillis(), jwt.secretKey());
  }

  private JwtUtils.Token createRefreshToken(String email) {
    SecurityProperties.Jwt jwt = securityProperties.jwt();
    return JwtUtils.createRefreshToken(email, jwt.refreshExpirationMillis(), jwt.secretKey());
  }

  private void assertTokenNotInvalidated(String subject, String token) {
    Optional<InvalidatedToken> optional =
        invalidatedTokenRepository.findBySubjectAndToken(subject, token);
    if (optional.isPresent()) {
      throw AuthenticationException.invalidToken("Refresh token is invalidated");
    }
  }
}
