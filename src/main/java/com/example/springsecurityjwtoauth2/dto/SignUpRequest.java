package com.example.springsecurityjwtoauth2.dto;

import com.example.springsecurityjwtoauth2.entity.Role;
import lombok.Data;

@Data
public class SignUpRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
