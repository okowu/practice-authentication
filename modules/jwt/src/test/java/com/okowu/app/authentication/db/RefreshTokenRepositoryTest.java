package com.okowu.app.authentication.db;

import static org.assertj.core.api.Assertions.assertThat;

import com.okowu.app.PostgreSQLContainerInitializer;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RefreshTokenRepositoryTest implements PostgreSQLContainerInitializer {

  @Autowired private RefreshTokenRepository refreshTokenRepository;

  @Test
  void testUserCreation() {
    String email = "kowuoscar@gmail.com";

    RefreshToken refreshTokenToCreate = new RefreshToken();
    refreshTokenToCreate.setSubject(email);
    refreshTokenToCreate.setToken("sample-refresh-token");
    refreshTokenToCreate.setExpiresAt(Instant.now().plusSeconds(5));
    refreshTokenToCreate.setUsed(false);

    Instant now = Instant.now();

    refreshTokenRepository.save(refreshTokenToCreate);

    List<RefreshToken> refreshTokens = refreshTokenRepository.findBySubject(email);

    assertThat(refreshTokens).hasSize(1);

    RefreshToken refreshToken = refreshTokens.getFirst();
    assertThat(refreshToken.getId()).isNotNull();
    assertThat(refreshToken.getToken()).isEqualTo(refreshTokenToCreate.getToken());
    assertThat(refreshToken.getSubject()).isEqualTo(email);
    assertThat(refreshToken.getCreatedAt()).isAfter(now);
    assertThat(refreshToken.getExpiresAt()).isEqualTo(refreshTokenToCreate.getExpiresAt());
    assertThat(refreshToken.isUsed()).isFalse();
  }
}
