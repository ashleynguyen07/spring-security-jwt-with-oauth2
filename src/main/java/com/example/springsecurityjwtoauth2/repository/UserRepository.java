package com.example.springsecurityjwtoauth2.repository;

import com.example.springsecurityjwtoauth2.entity.Role;
import com.example.springsecurityjwtoauth2.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    User findByEmail(String email);
    List<User> findByRole(Role role);
}
