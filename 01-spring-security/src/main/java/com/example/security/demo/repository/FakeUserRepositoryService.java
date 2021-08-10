package com.example.security.demo.repository;

import com.example.security.demo.model.User;
import com.google.common.collect.Lists;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static com.example.security.demo.security.UserRole.*;

@Repository("fake")
public class FakeUserRepositoryService implements UserRepository {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeUserRepositoryService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> findUserByUsername(String username) {
        return getUsers()
                .stream()
                .filter(user -> username.equals(user.getUsername()))
                .findFirst();
    }

    private List<User> getUsers() {

        List<User> users = Lists.newArrayList(
                User.builder().username("annasmith")
                        .password(passwordEncoder.encode("password"))
                        .grantedAuthorities(new ArrayList<>(STUDENT.getGrantedAuthorities()))
                        .isAccountNonExpired(true)
                        .isAccountNonLocked(true)
                        .isCredentialsNonExpired(true)
                        .isEnabled(true)
                        // NOTE: you can change List to Set in User model
                        .build(),
                User.builder().username("linda")
                        .password(passwordEncoder.encode("password123"))
                        .grantedAuthorities(new ArrayList<>(ADMIN.getGrantedAuthorities()))
                        .isAccountNonExpired(true)
                        .isAccountNonLocked(true)
                        .isCredentialsNonExpired(true)
                        .isEnabled(true)
                        .build(),
                User.builder()
                        .username("tom")
                        .password(passwordEncoder.encode("password123"))
                        .grantedAuthorities(new ArrayList<>(ADMIN_TRAINEE.getGrantedAuthorities()))
                        .isAccountNonExpired(true)
                        .isAccountNonLocked(true)
                        .isCredentialsNonExpired(true)
                        .isEnabled(true)
                        .build()
        );
        return users;
    }
}
