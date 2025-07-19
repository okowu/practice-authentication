package com.okowu.app.authentication.db;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

  List<RefreshToken> findBySubject(String subject);
}
