package com.example.springsecurityjwtoauth2.dto;

import lombok.Data;

@Data
public class SignInRequest {
    private String email;
    private String password;
}
