package com.gauri.generateToken.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {

    private String message;
    private String accessToken;
    private String refreshToken;
//    private long accessTokenExpiry;
}
