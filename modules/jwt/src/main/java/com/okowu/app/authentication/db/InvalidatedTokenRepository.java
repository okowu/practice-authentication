package com.okowu.app.authentication.db;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface InvalidatedTokenRepository extends JpaRepository<InvalidatedToken, Long> {

  Optional<InvalidatedToken> findBySubjectAndToken(String subject, String token);
}
