package com.okowu.app.user.db;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Setter
@Getter
@Entity
@EntityListeners(AuditingEntityListener.class)
@Table(name = "user", schema = "jwt")
public class User {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  public Long id;

  @Column(name = "email", nullable = false, unique = true)
  public String email;

  @Column(name = "username", nullable = false, unique = true)
  public String username;

  @Column(name = "password", nullable = false)
  public String password;

  @Column(name = "role", nullable = false)
  public String role;

  @CreatedDate
  @Column(name = "created_at", nullable = false, updatable = false)
  public Instant createdAt;

  @Column(name = "last_login")
  public Instant lastLogin;
}
