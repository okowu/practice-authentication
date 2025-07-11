package com.okowu.app.db;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@Entity
@AllArgsConstructor
@Table(name = "user", schema = "jwt")
public class User {

  @Id public Long id;

  @Column(name = "email", nullable = false, unique = true)
  public String email;

  @Column(name = "password", nullable = false)
  public String password;

  @Column(name = "roles", nullable = false)
  public Set<String> roles;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "last_login")
  public Instant lastLogin;
}
