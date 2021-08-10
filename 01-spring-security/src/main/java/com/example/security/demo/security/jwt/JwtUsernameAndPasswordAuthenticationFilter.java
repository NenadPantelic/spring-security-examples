package com.example.security.demo.security.jwt;

import com.example.security.demo.dto.UsernamePasswordAuthenticationReq;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UsernamePasswordAuthenticationReq authenticationReq = new ObjectMapper().readValue(request.getInputStream(), UsernamePasswordAuthenticationReq.class);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    authenticationReq.getUsername(), // principal
                    authenticationReq.getPassword()); // credentials
            // validate credentials
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // NOTE: will be invoked after attemptAuthentication success (if it fails, it won't be invoked)
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // create token and send it to the client
        String token = Jwts.builder()
                .setSubject(authResult.getName()) // name of the user -> sub of the claim
                .claim("authorities", authResult.getAuthorities()) // payload
                .setIssuedAt(new Date())
                .setExpiration(java.sql.Date.valueOf(
                        LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays()))) // expires in 2 weeks
                .signWith(secretKey) // should use strong keys
                .compact();
        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }

    /*
    * Request filters:
    * - perform some kind of processing/validation before request reaches the API -> we can reject the request or
    * pass it to the next filter or endpoint
    * - we have JwtUsernameAndPasswordAuthenticationFilter/UsernamePasswordAuthenticationFilter at this point
    * - after that, we have JwtTokenVerifier as a second filter
    * */
}
