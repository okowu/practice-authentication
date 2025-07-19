package com.okowu.app.user.schema;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.Length;

public record UserRegistrationRequest(
    @Email @NotBlank String email, @NotBlank @Length(min = 8) String password) {}
