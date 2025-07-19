package com.okowu.app.authentication;

public class AuthenticationException extends RuntimeException {

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public static AuthenticationException refreshTokenNotFound() {
        return new AuthenticationException("The given refresh value is not associated with any user");
    }
}
