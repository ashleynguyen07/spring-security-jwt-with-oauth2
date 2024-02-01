package com.example.springsecurityjwtoauth2.service;

import com.example.springsecurityjwtoauth2.entity.Role;
import com.example.springsecurityjwtoauth2.entity.User;
import com.example.springsecurityjwtoauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    @Autowired
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found!");
        }
        return (UserDetails) user;
    }


    public List<User> getListUser() {
        List<User> ls = userRepository.findByRole(Role.USER);
        return ls;
    }

    public List<User> getListAdmin() {
        List<User> ls = userRepository.findByRole(Role.ADMIN);
        return ls;
    }
}
