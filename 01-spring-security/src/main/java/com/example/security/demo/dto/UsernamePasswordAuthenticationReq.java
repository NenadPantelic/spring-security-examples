package com.example.security.demo.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Getter
@Setter
public class UsernamePasswordAuthenticationReq {
    private String username;
    private String password;

}
