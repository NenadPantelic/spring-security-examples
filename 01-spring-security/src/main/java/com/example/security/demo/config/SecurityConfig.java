package com.example.security.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.example.security.demo.security.UserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // for using annotation-based authorization
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    // 1. when the clients signs in, it receives CSRF (Cross-Site Request Forgery) token, which prevents
    // csrf attacks.
    // 2. When the user submits the form, the client sends CSRF token in the request.
    // 3.the server validates the token.
    // NOTE: GET requests work with CSRF, but POST/PUT/DELETE are protected

    /*WHEN TO USE CSRF PROTECTION?
     * By Spring docs:
     * for any request being used by normal users
     * if we have service that is used only by non-signed-in users, then we don't need it*/
    // X-XSRF-TOKEN (got from GET request)
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //.csrf().disable() // disable csrf
                // disable accessing to cookies from some client-side scripts
                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .authorizeRequests()
                .antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // allow only students to access student resources
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
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails adminUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123")) // password must be encoded
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        UserDetails adminTraineeUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123")) // password must be encoded
                .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
                .build();
        return new InMemoryUserDetailsManager(studentUser, adminUser, adminTraineeUser);
    }
}