package com.okowu.app.user.db;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.okowu.app.PostgreSQLContainerInitializer;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class UserRepositoryTest implements PostgreSQLContainerInitializer {

  @Autowired private UserRepository userRepository;

  @Test
  void testUserCreation() {
    String email = "kowuoscar@gmail.com";

    User userToCreate = new User();
    userToCreate.setEmail(email);
    userToCreate.setUsername("okowu");
    userToCreate.setPassword("password123");
    userToCreate.setRole("ROLE_USER");

    Instant now = Instant.now();

    userRepository.save(userToCreate);

    Optional<User> optionalUser = userRepository.findByEmail(email);

    assertThat(optionalUser).isPresent();

    User user = optionalUser.get();
    assertThat(user.getId()).isNotNull();
    assertThat(user.getEmail()).isEqualTo(userToCreate.getEmail());
    assertThat(user.getUsername()).isEqualTo(userToCreate.getUsername());
    assertThat(user.getPassword()).isEqualTo(userToCreate.getPassword());
    assertThat(user.getRole()).isEqualTo(userToCreate.getRole());
    assertThat(user.getCreatedAt()).isAfter(now);
  }

  @Test
  void testUserExistsByEmail() {
    String email = "kowuoscar@gmail.com";

    User user = new User();
    user.setEmail(email);
    user.setPassword("password123");
    user.setRole("ROLE_USER");

    userRepository.save(user);

    assertThat(userRepository.existsByEmail(email)).isTrue();
  }

  @Test
  void testUserEmailUniqueConstraint() {
    String email = "kowuoscar@gmail.com";

    User user = new User();
    user.setEmail(email);
    user.setPassword("password123");
    user.setRole("ROLE_USER");

    userRepository.save(user);

    // Attempt to create another user with the same email
    User duplicateUser = new User();
    duplicateUser.setEmail(email);
    duplicateUser.setPassword("anotherpassword");
    duplicateUser.setRole("ROLE_USER");

    assertThatThrownBy(() -> userRepository.save(duplicateUser))
        .isInstanceOf(DataIntegrityViolationException.class);
  }
}
