package com.okowu.app.utils;

import com.okowu.app.configuration.properties.SecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.Jwts;
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

  public record Token(String value, Date expirationDate) {}

  public static Token createAccessToken(
      String email, String username, String role, long expirationMillis, String encryptionKey) {
    Date expirationDate = expirationDate(expirationMillis);
    String jwt =
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .claim("username", username)
            .claim("role", role)
            .expiration(expirationDate)
            .encryptWith(secretKey(encryptionKey), Jwts.ENC.A256GCM)
            .compact();
    return new Token(jwt, expirationDate);
  }

  public static Token createRefreshToken(
      String email, long expirationMillis, String encryptionKey) {
    Date expirationDate = expirationDate(expirationMillis);
    String jwt =
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .expiration(expirationDate)
            .encryptWith(secretKey(encryptionKey), Jwts.ENC.A256GCM)
            .compact();
    return new Token(jwt, expirationDate);
  }

  public static Token getAccessToken(
      String email, String role, SecurityProperties securityProperties) {
    SecurityProperties.Jwt jwtProperties = securityProperties.jwt();
    Date expirationDate = expirationDate(jwtProperties.expirationMillis());
    return new Token(
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .claim("role", role)
            .expiration(expirationDate)
            .encryptWith(secretKey(jwtProperties.secretKey()), Jwts.ENC.A256GCM)
            .compact(),
        expirationDate);
  }

  public static Token generateAccessToken(
      String email, String role, long expirationMillis, String key) {
    Date expirationDate = expirationDate(expirationMillis);
    return new Token(
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .claim("role", role)
            .expiration(expirationDate)
            .encryptWith(secretKey(key), Jwts.ENC.A256GCM)
            .compact(),
        expirationDate);
  }

  public static Token getRefreshToken(String email, SecurityProperties securityProperties) {
    SecurityProperties.Jwt jwtProperties = securityProperties.jwt();
    Date expirationDate = expirationDate(jwtProperties.refreshExpirationMillis());
    return new Token(
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .expiration(expirationDate)
            .encryptWith(secretKey(jwtProperties.secretKey()), Jwts.ENC.A256GCM)
            .compact(),
        expirationDate);
  }

  public static Token generateRefreshToken(String email, long expirationMillis, String key) {
    Date expirationDate = expirationDate(expirationMillis);
    return new Token(
        Jwts.builder()
            .header()
            .and()
            .id(UUID.randomUUID().toString())
            .issuer(ISSUER)
            .issuedAt(new Date())
            .subject(email)
            .expiration(expirationDate)
            .encryptWith(secretKey(key), Jwts.ENC.A256GCM)
            .compact(),
        expirationDate);
  }

  public static Jwe<Claims> parseToken(String token, String key) {
    return Jwts.parser().decryptWith(secretKey(key)).build().parseEncryptedClaims(token);
  }

  private static Date expirationDate(long expirationMillis) {
    return Date.from(Instant.now().plusMillis(expirationMillis));
  }

  private static SecretKey secretKey(String key) {
    byte[] keyBytes = Base64.getDecoder().decode(key);
    return new SecretKeySpec(keyBytes, "AES");
  }
}
