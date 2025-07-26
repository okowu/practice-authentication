package com.okowu.app.authentication.service;

import static com.okowu.app.utils.JwtUtils.Token;

import com.okowu.app.authentication.db.RefreshToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import java.util.List;

public interface TokenService {

  record UserToken(Token accessToken, Token refreshToken) {}

  UserToken createUserToken(String email, String role);

  UserToken refreshUserToken(String email, String role, String token);

  Jwe<Claims> validateToken(String token);

  void invalidateToken(String email, String token);

  List<RefreshToken> findRefreshTokens(String email);

  RefreshToken findRefreshToken(String token);
}
