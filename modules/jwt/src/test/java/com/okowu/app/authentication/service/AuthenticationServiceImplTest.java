package com.okowu.app.authentication.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import static com.okowu.app.utils.JwtUtils.Token;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.okowu.app.TestUtils;
import com.okowu.app.authentication.AuthenticationException;
import com.okowu.app.authentication.db.RefreshToken;
import com.okowu.app.authentication.db.RefreshTokenRepository;
import com.okowu.app.authentication.schema.AuthenticationResponse;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.user.UserService;
import com.okowu.app.user.db.User;
import com.okowu.app.utils.JwtUtils;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplTest {

  @Mock UserService userService;
  @Mock SecurityProperties securityProperties;
  @Mock RefreshTokenRepository refreshTokenRepository;
  @Mock AuthenticationManager authenticationManager;
  @InjectMocks AuthenticationServiceImpl authenticationService;

  @Test
  void testLogin() {
    mockSecurityProperties();

    String email = "mytest@gmail.com";
    String password = "password";
    String role = "ROLE_ADMIN";

    var authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
    Authentication authentication = stubAuthentication(email, role);

    given(authenticationManager.authenticate(eq(authenticationToken))).willReturn(authentication);

    AuthenticationResponse authenticationResponse = authenticationService.login(email, password);
    assertThat(authenticationResponse.accessToken()).isNotBlank();
    assertThat(authenticationResponse.refreshToken()).isNotBlank();
    assertThat(authenticationResponse.expirationDate()).isNotNull();
  }

  @Test
  void testRefreshToken() {
    mockSecurityProperties();

    String email = "mydummymail";
    String secretKey = securityProperties.jwt().secretKey();
    Token refreshToken = JwtUtils.generateRefreshToken(email, 1000, secretKey);

    User user = new User();
    user.setEmail(email);
    user.setRole("ROLE_USER");

    RefreshToken refreshToken1 = createRefreshToken(email, "token1");
    RefreshToken refreshToken2 = createRefreshToken(email, "token2");
    RefreshToken refreshToken3 = createRefreshToken(email, "token3");
    RefreshToken matchingRefreshToken = createRefreshToken(email, refreshToken.value());

    List<RefreshToken> refreshTokens =
        List.of(refreshToken1, refreshToken2, refreshToken3, matchingRefreshToken);

    given(userService.findByEmail(email)).willReturn(user);
    given(refreshTokenRepository.findBySubject(email)).willReturn(refreshTokens);

    AuthenticationResponse response = authenticationService.refresh(refreshToken.value());
    assertThat(response.accessToken()).isNotBlank();
    assertThat(response.refreshToken()).isNotBlank();
    assertThat(response.expirationDate()).isNotNull();

    verify(userService).findByEmail(email);
    verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
  }

  @Test
  void testRefreshTokenShouldThrowExceptionWhenNotFound() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));

    String email = "mydummymail";
    String secretKey = securityProperties.jwt().secretKey();
    Token refreshToken = JwtUtils.generateRefreshToken(email, 1000, secretKey);

    User user = new User();
    user.setEmail(email);
    user.setRole("ROLE_USER");

    RefreshToken refreshToken1 = createRefreshToken(email, "token1");
    RefreshToken refreshToken2 = createRefreshToken(email, "token2");
    RefreshToken refreshToken3 = createRefreshToken(email, "token3");
    RefreshToken refreshToken4 = createRefreshToken(email, "token4");

    List<RefreshToken> refreshTokens =
            List.of(refreshToken1, refreshToken2, refreshToken3, refreshToken4);

    given(userService.findByEmail(email)).willReturn(user);
    given(refreshTokenRepository.findBySubject(email)).willReturn(refreshTokens);

    assertThatThrownBy(() -> authenticationService.refresh(refreshToken.value()))
        .isInstanceOf(AuthenticationException.class)
        .hasMessage("The given refresh value is not associated with any user");
  }

  private Authentication stubAuthentication(String email, String role) {
    var authentication = mock(UsernamePasswordAuthenticationToken.class);

    UserDetails userDetails = mock(UserDetails.class);
    List<GrantedAuthority> authorities =
        Collections.singletonList(new SimpleGrantedAuthority(role));
    given(userDetails.getUsername()).willReturn(email);
    given(userDetails.getAuthorities()).willReturn((List) authorities);

    given(authentication.getPrincipal()).willReturn(userDetails);
    return authentication;
  }

  private RefreshToken createRefreshToken(String email, String token) {
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setSubject(email);
    refreshToken.setToken(token);
    return refreshToken;
  }

  private void mockSecurityProperties() {
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
    given(jwtProperties.expirationMillis()).willReturn(1000L);
    given(jwtProperties.refreshExpirationMillis()).willReturn(1000L);
  }
}
