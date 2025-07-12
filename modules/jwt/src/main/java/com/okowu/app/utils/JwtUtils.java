package com.okowu.app.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.lang.Assert;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtUtils {

  private static final String ISSUER = "JWT_APP";
  private static final long DEFAULT_EXPIRATION_MILLIS = 3600;

  public static String createJwt(String base64Key, long expirationMillis) {
    byte[] keyBytes = Base64.getDecoder().decode(base64Key);
    SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
    return Jwts.builder()
        .header()
        .and()
        .id(UUID.randomUUID().toString())
        .issuer(ISSUER)
        .issuedAt(new Date())
        .expiration(calculateExpirationDate(expirationMillis))
        .encryptWith(secretKey, Jwts.ENC.A256GCM)
        .compact();
  }

  public static Jwe<Claims> parseJwt(String base64Key, String jwt) {
    Assert.hasText(jwt);
    byte[] keyBytes = Base64.getDecoder().decode(base64Key);
    SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
    return Jwts.parser().decryptWith(secretKey).build().parseEncryptedClaims(jwt);
  }

  private static Date calculateExpirationDate(long expirationMillis) {
    return Date.from(Instant.now().plusMillis(expirationMillis));
  }
}
