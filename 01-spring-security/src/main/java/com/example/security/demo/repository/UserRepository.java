package com.example.security.demo.repository;

import com.example.security.demo.model.User;

import java.util.Optional;

public interface UserRepository {
    Optional<User> findUserByUsername(String username);
}
