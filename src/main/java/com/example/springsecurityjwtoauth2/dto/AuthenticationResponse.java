package com.example.springsecurityjwtoauth2.dto;

import lombok.Data;

@Data
public class AuthenticationResponse {
    private String token;
    private String refreshToken;

}
