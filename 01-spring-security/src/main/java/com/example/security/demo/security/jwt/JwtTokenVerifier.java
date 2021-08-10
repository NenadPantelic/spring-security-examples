package com.example.security.demo.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

// executes only once per request
public class JwtTokenVerifier extends OncePerRequestFilter {

   private final SecretKey secretKey;
   private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        // invalid header -> no header value or header value doesn't start with Bearer -> reject it
        if (Strings.isNullOrEmpty(authHeader) || !authHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }
        // remove Bearer from the token value
        String token = authHeader.replace(jwtConfig.getTokenPrefix(), "");
        try {
            // JWT after compaction is called JWS
            /*
            1. Use the Jwts.parserBuilder() method to create a JwtParserBuilder instance.
            2. Specify the SecretKey or asymmetric PublicKey you want to use to verify the JWS signature.1
            3. Call the build() method on the JwtParserBuilder to return a thread-safe JwtParser.
            4. Finally, call the parseClaimsJws(String) method with your jws String, producing the original JWS.
            5. The entire call is wrapped in a try/catch block in case parsing or signature validation fails. We'll cover exceptions and causes for failure later.
            * */
            Jws<Claims> jws = jws = Jwts.parserBuilder()  // (1)
                    .setSigningKey(secretKey)         // (2)
                    .build()                    // (3)
                    .parseClaimsJws(token);  // (4)

            Claims body = jws.getBody();
            String username = body.getSubject();
            var authorities = (List<Map<String, String>>) body.get("authorities");
            Set<SimpleGrantedAuthority> grantedAuthorities = authorities
                    .stream()
                    .map(m -> new SimpleGrantedAuthority((m.get("authority"))))
                    .collect(Collectors.toSet());

            System.out.println(jws.getHeader());
            System.out.println(body);
            System.out.println(username);
            System.out.println(jws.getSignature());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    grantedAuthorities);
            // client is authenticated now
            SecurityContextHolder.getContext().setAuthentication(authentication);


        } catch (JwtException e) { // (5)
            throw new IllegalStateException(String.format("Token %s cannot be trusted!", token));
        }
        // proceed with the next filter
        filterChain.doFilter(request, response);
    }
}

