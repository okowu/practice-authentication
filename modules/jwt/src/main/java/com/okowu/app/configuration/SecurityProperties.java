package com.okowu.app.configuration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security")
public record SecurityProperties(@Valid Jwt jwt) {

  public record Jwt(@NotBlank String secretKey, @NotBlank String issuer, long expirationMillis) {}
}
