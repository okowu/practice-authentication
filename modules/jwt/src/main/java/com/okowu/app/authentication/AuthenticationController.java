package com.okowu.app.authentication;

import com.okowu.app.authentication.schema.LoginRequest;
import com.okowu.app.authentication.schema.LoginResponse;
import com.okowu.app.authentication.schema.TokenPayload;
import com.okowu.app.authentication.service.AuthenticationService;
import com.okowu.app.utils.SecurityUtils;
import jakarta.servlet.http.HttpServletRequest;
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
  public ResponseEntity<LoginResponse> login(@RequestBody @Valid LoginRequest request) {
    return ResponseEntity.ok(authenticationService.login(request.email(), request.password()));
  }

  @PostMapping("/refresh")
  public ResponseEntity<LoginResponse> refresh(@RequestBody @Valid TokenPayload request) {
    return ResponseEntity.ok(authenticationService.refresh(request.token()));
  }

  @PostMapping("/logout")
  public ResponseEntity<LoginResponse> logout(
      HttpServletRequest request, @RequestBody TokenPayload tokenPayload) {
    String accessToken = SecurityUtils.extractAccessToken(request);
    authenticationService.logout(accessToken, tokenPayload.token());
    return ResponseEntity.ok().build();
  }
}
