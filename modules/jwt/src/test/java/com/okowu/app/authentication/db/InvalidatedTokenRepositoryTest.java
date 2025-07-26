package com.okowu.app.authentication.db;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import com.okowu.app.PostgreSQLContainerInitializer;
import com.okowu.app.TestUtils;
import com.okowu.app.configuration.properties.SecurityProperties;
import com.okowu.app.utils.JwtUtils;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class InvalidatedTokenRepositoryTest implements PostgreSQLContainerInitializer {

  @Autowired private InvalidatedTokenRepository invalidatedTokenRepository;

  @Test
  void testInvalidatedTokenCreation() {
    String email = "kowuoscar@gmail.com";

    SecurityProperties securityProperties = mock(SecurityProperties.class);
    SecurityProperties.Jwt jwtProperties = mock(SecurityProperties.Jwt.class);
    given(securityProperties.jwt()).willReturn(jwtProperties);
    given(jwtProperties.secretKey()).willReturn(TestUtils.generateRandomKey(32));
    given(jwtProperties.expirationMillis()).willReturn(1000L);

    JwtUtils.Token token = JwtUtils.getAccessToken(email, "USER", securityProperties);

    InvalidatedToken invalidatedTokenToCreate = new InvalidatedToken();
    invalidatedTokenToCreate.setSubject(email);
    invalidatedTokenToCreate.setToken(token.value());

    Instant now = Instant.now();

    invalidatedTokenRepository.save(invalidatedTokenToCreate);

    Optional<InvalidatedToken> optionalInvalidatedToken =
        invalidatedTokenRepository.findBySubjectAndToken(email, token.value());

    assertThat(optionalInvalidatedToken).isPresent();

    InvalidatedToken invalidatedToken = optionalInvalidatedToken.get();
    assertThat(invalidatedToken.getId()).isNotNull();
    assertThat(invalidatedToken.getSubject()).isEqualTo(email);
    assertThat(invalidatedToken.getToken()).isEqualTo(token.value());
    assertThat(invalidatedToken.getCreatedAt()).isAfter(now);
  }
}
