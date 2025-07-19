package com.okowu.app.authentication.schema;

import jakarta.validation.constraints.NotBlank;

public record TokenPayload(@NotBlank String token) {}
