package com.example.security.demo.config;

import com.example.security.demo.security.UserPermission;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.security.demo.security.UserRole.*;
import static com.example.security.demo.security.UserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // for using annotation-based authorization
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // drawback of the basic auth -> there is no logout
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // every request must be authenticated => user must provide username and password
        // Header:
        // Authorization: Basic <Base64 encoded string>
        // Security provides default user stored in-memory:
        // username: user
        // password: random UUID
        http
                .csrf().disable() // disable csrf
                .authorizeRequests()
                // these paths do not require authentication
                .antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // allow only students to access student resources
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(STUDENT_WRITE.getPermission())
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMIN_TRAINEE.name()) // both can read
                .anyRequest() //-> any path
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    // to retrieve users from the db
    // defining custom user stored in-memory
    protected UserDetailsService userDetailsService() {
        UserDetails studentUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password")) // password must be encoded
                //.roles("STUDENT") //  internally stored as ROLE_STUDENT
//                .roles(STUDENT.name()) //  internally stored as ROLE_STUDENT
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123")) // password must be encoded
                //.roles("ADMIN") //  internally stored as ROLE_ADMIN
//                .roles(ADMIN.name()) //  internally stored as ROLE_ADMIN
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        UserDetails adminTraineeUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123")) // password must be encoded
                //.roles("ADMIN") //  internally stored as ROLE_ADMIN
//                .roles(ADMIN_TRAINEE.name()) //  internally stored as ROLE_ADMIN
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(studentUser, adminUser, adminTraineeUser);
    }
    // roles -> container of authorities/permissions
    // e.g. -> role = admin
    // student:read, student:write, course:read, course:write
    // e.g. -> role = student
    // student:read, student:write, course:read
}