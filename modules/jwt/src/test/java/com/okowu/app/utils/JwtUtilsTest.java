package com.okowu.app.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import static com.okowu.app.utils.JwtUtils.Token;

import com.okowu.app.TestUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.security.WeakKeyException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

public class JwtUtilsTest {
  static String SECRET_KEY = "kY6Mx5F9Ofq6zGyN7FzixTzqsArPQquO9jrpJDh+NDE=";
  static String EMAIL = "mytest@gmail.com";
  static String ROLE = "mydummyrole";

  @Test
  void testGenerateAccessToken() {
    Instant now = Instant.now();
    Token accessToken = JwtUtils.generateAccessToken(EMAIL, ROLE, 5, SECRET_KEY);

    assertThat(accessToken.value()).isNotBlank();
    assertThat(accessToken.expirationDate()).isAfterOrEqualTo(now.plusMillis(5));
  }

  @Test
  void testParseAccessToken() {
    Token accessToken = JwtUtils.generateAccessToken(EMAIL, ROLE, 1000, SECRET_KEY);

    Jwe<Claims> jwe = JwtUtils.parseToken(accessToken.value(), SECRET_KEY);
    assertThat(jwe).isNotNull();
    assertThat(jwe.getPayload().getSubject()).isEqualTo(EMAIL);
  }

  @Test
  void testGenerateRefreshToken() {
    Instant now = Instant.now();
    Token refreshToken = JwtUtils.generateRefreshToken(EMAIL, 5, SECRET_KEY);

    assertThat(refreshToken.value()).isNotBlank();
    assertThat(refreshToken.expirationDate()).isAfterOrEqualTo(now.plusSeconds(5));
  }

  @Test
  void testGenerateAccessTokenShouldFailGivenInvalidEncryptionKey() {
    String invalidKey = TestUtils.generateRandomKey(31);

    assertThatThrownBy(() -> JwtUtils.generateAccessToken(EMAIL, ROLE, 10, invalidKey))
        .isInstanceOf(WeakKeyException.class);
  }
}
