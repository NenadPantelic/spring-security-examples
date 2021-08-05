package com.example.security.demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
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
                .authorizeRequests()
                // these paths do not require authentication
                .antMatchers("/", "/index", "/css/*", "/js/*")
                .permitAll()
                .anyRequest() //-> any path
                .authenticated()
                .and()
                .httpBasic();
    }
}
