package com.okowu.app.db;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@Entity
@AllArgsConstructor
@Table(name = "document", schema = "jwt")
public class Document {

  @Id public Long id;

  @Column(name = "title", nullable = false, unique = true)
  public String title;

  @Column(name = "owner_id", nullable = false)
  public Long ownerId;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;

  @Column(name = "visibility", nullable = false)
  public int visibility;
}
