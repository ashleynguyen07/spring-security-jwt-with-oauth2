package com.example.springsecurityjwtoauth2.controller;

import com.example.springsecurityjwtoauth2.repository.UserRepository;
import com.example.springsecurityjwtoauth2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/myapplication/user")
@RequiredArgsConstructor
public class UserController {

    @GetMapping
    public ResponseEntity<String> home() {
        return ResponseEntity.ok("Hi User");
    }
}
