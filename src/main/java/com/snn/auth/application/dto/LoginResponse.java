package com.snn.auth.application.dto;

import java.util.List;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginResponse {

  private final String token;
  private final String type = "Bearer";
  private final Long id;
  private final String username;
  private final String email;
  private final List<String> roles;

  public LoginResponse(String token, Long id, String username, String email, List<String> roles) {
    this.token = token;
    this.id = id;
    this.username = username;
    this.email = email;
    this.roles = roles;
  }
}
