package com.example.springsecurity.jwt;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class LoginResponse {
    public String jwtToken;
    public String username;
    public List<String> roles;
}
