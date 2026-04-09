package com.gauri.generateToken.controller;

import com.gauri.generateToken.dto.JwtResponse;
import com.gauri.generateToken.dto.LoginRequest;
import com.gauri.generateToken.dto.RefreshRequest;
import com.gauri.generateToken.security.JwtUtil;
import com.gauri.generateToken.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody LoginRequest request) {
        return authService.register(request);
    }

    @PostMapping("/login")
    public JwtResponse login(@RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        // Auto-capture from browser
        String ipAddress = getClientIpAddress(httpRequest);  // Auto-detected
        String userAgent = httpRequest.getHeader("User-Agent");  // Auto-detected

        // Set to your request object or pass directly to service
        request.setIpAddress(ipAddress);
        request.setUserAgent(userAgent);
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public JwtResponse refresh(@RequestBody RefreshRequest request, HttpServletRequest httpRequest) {

        String ipAddress = getClientIpAddress(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        return authService.refresh(request.getRefreshToken(), ipAddress, userAgent);
    }

    @PostMapping("/logout")
    public String logout(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "No token provided");
        }

        String token = authHeader.substring(7);
        String sessionId = jwtUtil.extractSessionId(token);

        return authService.logout(sessionId);
    }

//    @PostMapping("/logout-all")
//    public String logoutAll(Authentication authentication) {
//        String username = authentication.getName();
//        return authService.logoutAll(username);
//    }


    // Get real client IP (handles proxies)
    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("X-Real-IP");
        }

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }

        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        // If behind proxy, X-Forwarded-For contains multiple IPs (client, proxy1, proxy2)
        // Take the first one (original client)
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress != null ? ipAddress : "unknown";
    }
}