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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.security.demo.security.UserRole.*;


/*
 * Basic auth:
 * - (in header) Authorization: Basic <Base64 encoded -> username:password>
 * - HTTPS recommended
 * - Simple and fast
 * - Can't logout
 *
 * Client            Server
 *  GET request ----->
 * <-----Unauthorized---
 *
 * ---GET request | Base64 username:password--
 * <-------200 OK----------
 *
 *
 * Form-based auth:
 * - Username and password
 * - Standard in most websites
 * - Forms (full control)
 * - Can logout
 * - HTTPS recommended
 *
 * Client            Server
 * ----POST username password----
 *                               |
 *                               |
 *     validates credentials<-----
 * <-------OK--------------------
 * <-------COOKIE SESSIONID------
 *
 * Any request with SESSIONID----->
 *                                |
 *      validates SESSIONID<-------
 * <--------OK---------------------
 *
 * -SESSIONID expires after 30 mins of inactivity, can be prolonged with remember me
 * */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) // for using annotation-based authorization
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // disable csrf
                .authorizeRequests()
                .antMatchers("/", "/index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // allow only students to access student resources
                .anyRequest() //-> any path
                .authenticated()
                .and()
//                .httpBasic(); // -> for basic auth
                // session id is stored in-memory, but we can use e.g. Postgres or Redis
                .formLogin() //  -> for form-based auth
                    .loginPage("/login")
                    .permitAll() // custom login page
                    .defaultSuccessUrl("/courses", true) // redirect after successful login
                    .usernameParameter("username") // default value => username, can be customized
                    .passwordParameter("password") // default value => password, can be customized
                .and()
                .rememberMe() // defaults to 2 weeks; remember-me cookie, also stored in the database
                // (by default stored in-memory)
                // remember-me cookie:
                // - username
                // - expiration time
                // - MD5 of these two values
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // set expiration time frame
                    .key("somethingverysecure") // custom key used to hash with MD5
                    .rememberMeParameter("remember-me") // default value => remember-me, can be customized
                .and()
                .logout()
                    .logoutUrl("/logout") // default url is /logout
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // this happens
                    // under the hood when CSRF protection is disabled. If it is enabled, this line should be remove
                    .clearAuthentication(true) // clear auth
                    .invalidateHttpSession(true) // invalidate session
                    .deleteCookies("JSESSIONID", "remember-me") // delete session cookies
                    .logoutSuccessUrl("/login");
        // if CSRF protection is enabled, logout request must be POST
        // otherwise, any HTTP method is allowed


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