package com.gauri.generateToken.dto;

import lombok.Data;

@Data
public class RefreshRequest {

    private String refreshToken;
    private String ipAddress;
    private String userAgent;
}
