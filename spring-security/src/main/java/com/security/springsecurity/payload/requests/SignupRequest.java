package com.security.springsecurity.payload.requests;

import lombok.Data;

import java.util.Set;
@Data
public class SignupRequest {
    private String username;
    private String email;
    private String password;
    private Set<String> roles;
}