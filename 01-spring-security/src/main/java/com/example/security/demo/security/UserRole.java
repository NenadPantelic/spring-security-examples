package com.example.security.demo.security;

import com.google.common.collect.Sets;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

@Getter
public enum UserRole {
    STUDENT(Sets.newHashSet()), // zero permissions
    ADMIN(Sets.newHashSet(UserPermission.COURSE_READ, UserPermission.COURSE_WRITE,
            UserPermission.STUDENT_READ, UserPermission.STUDENT_WRITE)), // zero or more permissions ;
    ADMIN_TRAINEE(Sets.newHashSet(UserPermission.COURSE_READ, UserPermission.STUDENT_READ));

    private final Set<UserPermission> permissions;

    UserRole(Set<UserPermission> permissions) {
        this.permissions = permissions;
    }

    // granted authorities are roles and authorities (permissions)
    public Set<SimpleGrantedAuthority> getGrantedAuthorities() {
        // add permissions for this role
        Set<SimpleGrantedAuthority> authorities = getPermissions()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        // add role
        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
        return authorities;
    }
}
