package com.example.springsecurityjwtoauth2.controller;

import com.example.springsecurityjwtoauth2.dto.AuthenticationResponse;
import com.example.springsecurityjwtoauth2.dto.SignInRequest;
import com.example.springsecurityjwtoauth2.dto.SignUpRequest;
import com.example.springsecurityjwtoauth2.entity.User;
import com.example.springsecurityjwtoauth2.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/myapplication")
public class LoginController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<User> registerUser(@RequestBody SignUpRequest signUpRequest) {
        return ResponseEntity.ok(authenticationService.signup(signUpRequest));
    }

    @PostMapping("/signin")
    public ResponseEntity<AuthenticationResponse> signin(@RequestBody SignInRequest signInRequest) {
        return ResponseEntity.ok(authenticationService.signin(signInRequest));
    }

    @GetMapping("/home")
    public String home() {
        return "Login Success!";
    }


}