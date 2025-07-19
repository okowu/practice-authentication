package com.okowu.app.authentication.schema;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

public record LoginRequest(
    @Email @NotBlank String email, @Length(min = 8) @NotBlank String password) {}
