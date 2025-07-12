package com.okowu.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.WeakKeyException;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.Test;

public class JwtUtilsTest {

  static String key = "kY6Mx5F9Ofq6zGyN7FzixTzqsArPQquO9jrpJDh+NDE=";

  @Test
  public void testCreateJwt() {
    String jwt = JwtUtils.createJwt(key, 1);
    assertThat(jwt).isNotBlank();
  }

  @Test
  public void testCreateJwtShouldFailGivenInvalidLengthKey() {
    byte[] bytes = new byte[31];
    new SecureRandom().nextBytes(bytes);
    String invalidKey = Base64.getEncoder().encodeToString(bytes);

    assertThatThrownBy(() -> JwtUtils.createJwt(invalidKey, 1))
        .isInstanceOf(WeakKeyException.class);
  }

  @Test
  public void testParseJwt() {
    String jwt = JwtUtils.createJwt(key, 1000);

    Jwe<Claims> jwe = JwtUtils.parseJwt(key, jwt);
    assertThat(jwe).isNotNull();
  }

  @Test
  public void testParseJwtShouldFailGivenInvalidKey() {
    String jwt = JwtUtils.createJwt(key, 3);

    byte[] bytes = new byte[32];
    new SecureRandom().nextBytes(bytes);
    String invalidKey = Base64.getEncoder().encodeToString(bytes);

    assertThatThrownBy(() -> JwtUtils.parseJwt(invalidKey, jwt)).isInstanceOf(JwtException.class);
  }

  @Test
  public void testParseJwtShouldFailGivenExpired() throws InterruptedException {
    String jwt = JwtUtils.createJwt(key, 1);

    Thread.sleep(2);

    assertThatThrownBy(() -> JwtUtils.parseJwt(key, jwt)).isInstanceOf(ExpiredJwtException.class);
  }
}
