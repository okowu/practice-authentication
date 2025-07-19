package com.okowu.app.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verify;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.okowu.app.TestUtils;
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
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class TokenServiceTest {

  @Mock SecurityProperties securityProperties;
  @Mock RefreshTokenRepository refreshTokenRepository;
  @Mock InvalidatedTokenRepository invalidatedTokenRepository;
  @InjectMocks TokenService tokenService;

  String email = "email@email.com";
  String role = "USER";

  @Test
  void testGetLoginToken() {
    mockSecurityProperties();

    TokenService.LoginToken loginToken = tokenService.getLoginToken(email, role);
    assertThat(loginToken).isNotNull();
    assertThat(loginToken.accessToken()).isNotNull();
    assertThat(loginToken.accessToken().value()).isNotBlank();
    assertThat(loginToken.refreshToken()).isNotNull();
    assertThat(loginToken.refreshToken().value()).isNotBlank();

    verify(refreshTokenRepository).save(any(RefreshToken.class));
    verifyNoMoreInteractions(refreshTokenRepository);
    verifyNoInteractions(invalidatedTokenRepository);
  }

  @Test
  void testFindRefreshToken() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));

    String secretKey = securityProperties.jwt().secretKey();
    JwtUtils.Token refreshToken = JwtUtils.generateRefreshToken(email, 1000, secretKey);

    RefreshToken refreshToken1 = createRefreshToken(email, "token1");
    RefreshToken refreshToken2 = createRefreshToken(email, "token2");
    RefreshToken refreshToken3 = createRefreshToken(email, "token3");
    RefreshToken matchingRefreshToken = createRefreshToken(email, refreshToken.value());

    List<RefreshToken> refreshTokens =
        List.of(refreshToken1, refreshToken2, refreshToken3, matchingRefreshToken);

    given(invalidatedTokenRepository.findBySubjectAndToken(email, refreshToken.value()))
        .willReturn(Optional.empty());
    given(refreshTokenRepository.findBySubject(email)).willReturn(refreshTokens);

    RefreshToken foundRefreshToken = tokenService.findRefreshToken(refreshToken.value());
    assertThat(foundRefreshToken).isEqualTo(matchingRefreshToken);

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, refreshToken.value());
    verify(refreshTokenRepository).findBySubject(email);
  }

  @Test
  void testFindRefreshTokenShouldThrowInvalidTokenException() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));

    String secretKey = securityProperties.jwt().secretKey();
    JwtUtils.Token refreshToken = JwtUtils.generateRefreshToken(email, 1000, secretKey);

    given(invalidatedTokenRepository.findBySubjectAndToken(email, refreshToken.value()))
        .willReturn(Optional.of(new InvalidatedToken()));

    assertThatThrownBy(() -> tokenService.findRefreshToken(refreshToken.value()))
        .isInstanceOf(AuthenticationException.class)
        .extracting("message")
        .isEqualTo("The given token is invalid");

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, refreshToken.value());
    verifyNoInteractions(refreshTokenRepository);
  }

  @Test
  void testFindRefreshTokenShouldThrowTokenNotFoundException() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));

    String secretKey = securityProperties.jwt().secretKey();
    JwtUtils.Token refreshToken = JwtUtils.generateRefreshToken(email, 1000, secretKey);

    RefreshToken refreshToken1 = createRefreshToken(email, "token1");
    RefreshToken refreshToken2 = createRefreshToken(email, "token2");
    RefreshToken refreshToken3 = createRefreshToken(email, "token3");
    RefreshToken refreshToken4 = createRefreshToken(email, "token4");

    List<RefreshToken> refreshTokens =
        List.of(refreshToken1, refreshToken2, refreshToken3, refreshToken4);

    given(invalidatedTokenRepository.findBySubjectAndToken(email, refreshToken.value()))
        .willReturn(Optional.empty());
    given(refreshTokenRepository.findBySubject(email)).willReturn(refreshTokens);

    assertThatThrownBy(() -> tokenService.findRefreshToken(refreshToken.value()))
        .isInstanceOf(AuthenticationException.class)
        .extracting("message")
        .isEqualTo("The refresh token is not associated with any user");

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, refreshToken.value());
    verify(refreshTokenRepository).findBySubject(email);
  }

  @Test
  void testRefreshToken() {

    mockSecurityProperties();

    User user = new User();
    user.setEmail(email);

    RefreshToken refreshToken = createRefreshToken(email, "token1");
    assertThat(refreshToken.isUsed()).isFalse();

    given(invalidatedTokenRepository.findBySubjectAndToken(email, refreshToken.getToken()))
        .willReturn(Optional.empty());

    TokenService.LoginToken loginToken = tokenService.refreshToken(user, refreshToken);

    assertThat(refreshToken.isUsed()).isTrue();

    assertThat(loginToken).isNotNull();
    assertThat(loginToken.accessToken()).isNotNull();
    assertThat(loginToken.accessToken().value()).isNotBlank();
    assertThat(loginToken.refreshToken()).isNotNull();
    assertThat(loginToken.refreshToken().value()).isNotBlank();

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, refreshToken.getToken());
    verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
  }

  @Test
  void testRefreshTokenShouldThrowInvalidTokenException() {

    User user = new User();
    user.setEmail(email);

    RefreshToken refreshToken = createRefreshToken(email, "token1");

    given(invalidatedTokenRepository.findBySubjectAndToken(email, refreshToken.getToken()))
        .willReturn(Optional.of(new InvalidatedToken()));

    assertThatThrownBy(() -> tokenService.refreshToken(user, refreshToken))
        .isInstanceOf(AuthenticationException.class)
        .extracting("message")
        .isEqualTo("The given token is invalid");

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, refreshToken.getToken());
    verifyNoInteractions(refreshTokenRepository);
  }

  @Test
  void testValidateToken() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
    given(jwtProperties.expirationMillis()).willReturn(1000L);

    JwtUtils.Token token = JwtUtils.getAccessToken(email, role, securityProperties);

    given(invalidatedTokenRepository.findBySubjectAndToken(email, token.value()))
        .willReturn(Optional.empty());

    Jwe<Claims> jwt = tokenService.validateToken(token.value());
    assertThat(jwt).isNotNull();
    assertThat(jwt.getPayload().getSubject()).isEqualTo(email);

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, token.value());
  }

  @Test
  void testValidateTokenShouldThrowInvalidTokenException() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
    given(jwtProperties.expirationMillis()).willReturn(1000L);

    JwtUtils.Token token = JwtUtils.getAccessToken(email, role, securityProperties);

    given(invalidatedTokenRepository.findBySubjectAndToken(email, token.value()))
        .willReturn(Optional.of(new InvalidatedToken()));

    assertThatThrownBy(() -> tokenService.validateToken(token.value()))
        .isInstanceOf(AuthenticationException.class)
        .extracting("message")
        .isEqualTo("The given token is invalid");

    verify(invalidatedTokenRepository).findBySubjectAndToken(email, token.value());
  }

  private void mockSecurityProperties() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
    given(jwtProperties.expirationMillis()).willReturn(1000L);
    given(jwtProperties.refreshExpirationMillis()).willReturn(1000L);
  }

  private void mockSecuritySecretKey() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
  }

  private RefreshToken createRefreshToken(String email, String token) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setSubject(email);
    refreshToken.setToken(token);
    refreshToken.setUsed(false);
    return refreshToken;
  }
}
