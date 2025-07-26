package com.okowu.app.authentication;

import com.okowu.app.authentication.schema.AuthenticationRequest;
import com.okowu.app.authentication.schema.AuthenticationSuccess;
import com.okowu.app.authentication.schema.TokenPayload;
import com.okowu.app.authentication.service.AuthenticationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @PostMapping("/login")
  public ResponseEntity<AuthenticationSuccess> login(
      @RequestBody @Valid AuthenticationRequest request) {
    return ResponseEntity.ok(authenticationService.login(request.email(), request.password()));
  }

  @PostMapping("/refresh")
  public ResponseEntity<AuthenticationSuccess> refresh(@RequestBody @Valid TokenPayload request) {
    return ResponseEntity.ok(authenticationService.refresh(request.token()));
  }
}
