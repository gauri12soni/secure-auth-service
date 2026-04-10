package com.gauri.generateToken.service;

import com.gauri.generateToken.dto.JwtResponse;
import com.gauri.generateToken.dto.LoginRequest;
import com.gauri.generateToken.entity.RefreshToken;
import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import com.gauri.generateToken.repository.RefreshTokenRepository;
import com.gauri.generateToken.repository.SessionRepository;
import com.gauri.generateToken.repository.UserRepository;
import com.gauri.generateToken.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private SessionRepository sessionRepository;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Value("${jwt.access.expiration}")
    private long accessExp;

    @Value("${jwt.refresh.expiration}")
    private long refreshExp;

    // Hash function
    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    private String generateSecureToken() {
        return UUID.randomUUID().toString() + "." + UUID.randomUUID().toString();
    }

    // ================= REGISTER =================
    public ResponseEntity<?> register(LoginRequest request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        return new ResponseEntity<>(Map.of("message", "User registered successfully"), HttpStatus.CREATED);
    }
//
//    // ================= LOGIN =================
//    // Accepts LoginRequest (IP and UserAgent already inside request object)
//    @Transactional
//    public JwtResponse login(LoginRequest request) {
//        // Authenticate
//        try {
//            authenticationManager.authenticate(
//                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
//            );
//        } catch (BadCredentialsException e) {
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
//        }
//
//        User user = userRepository.findByUsername(request.getUsername())
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));
//
//        // Get IP and User-Agent from request object (already set by controller)
//        String ipAddress = request.getIpAddress() != null ? request.getIpAddress() : "unknown-ip";
//        String userAgent = request.getUserAgent() != null ? request.getUserAgent() : "unknown-agent";
//
//        // Delete old session completely
//        sessionRepository.findByUser(user).ifPresent(oldSession -> {
//            refreshTokenRepository.deleteBySession(oldSession);
//            sessionRepository.delete(oldSession);
//            sessionRepository.flush();
//        });
//
//        // Create new session
//        Session session = new Session();
//        session.setSessionId(UUID.randomUUID().toString());
//        session.setUser(user);
//        session.setIpAddress(ipAddress);
//        session.setUserAgent(userAgent);
//        session.setCreatedAt(Instant.now());
//        session.setExpiresAt(Instant.now().plusMillis(refreshExp));
//        session.setLastActive(Instant.now());
//        sessionRepository.save(session);
//
//        // Create refresh token
//        String rawRefreshToken = generateSecureToken();
//        RefreshToken refreshToken = new RefreshToken();
//        refreshToken.setTokenHash(sha256(rawRefreshToken));
//        refreshToken.setSession(session);
//        refreshToken.setCreatedAt(Instant.now());
//        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExp));
//        refreshToken.setRevoked(false);
//        refreshTokenRepository.save(refreshToken);
//
//        // Create access token
//        String accessToken = jwtUtil.generateToken(user.getUsername(), session.getSessionId(), accessExp);
//
//        return new JwtResponse("Login successful", accessToken, rawRefreshToken);
//    }


    // ================= LOGIN =================
    @Transactional
    public JwtResponse login(LoginRequest request) {
        // Authenticate
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (BadCredentialsException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid username or password");
        }

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found"));

        String ipAddress = request.getIpAddress() != null ? request.getIpAddress() : "unknown-ip";
        String userAgent = request.getUserAgent() != null ? request.getUserAgent() : "unknown-agent";

        // Find and REVOKE old session
        Optional<Session> existingSession = sessionRepository.findByUser(user);
        if (existingSession.isPresent()) {
            Session oldSession = existingSession.get();
//            oldSession.setRevoked(true);  // Revoke old session
//            sessionRepository.save(oldSession);
//            sessionRepository.flush();  // Force flush to ensure it's saved

            refreshTokenRepository.deleteBySession(oldSession);
            sessionRepository.delete(oldSession);  // DELETE, not update
            sessionRepository.flush();

        }
        //  Create NEW session (active)
        Session session = new Session();
        session.setSessionId(UUID.randomUUID().toString());
        session.setUser(user);
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setCreatedAt(Instant.now());
        session.setExpiresAt(Instant.now().plusMillis(refreshExp));
        session.setLastActive(Instant.now());
//        session.setRevoked(false);  // New session is active
        sessionRepository.saveAndFlush(session);

        // Create refresh token
        String rawRefreshToken = generateSecureToken();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(sha256(rawRefreshToken));
        refreshToken.setSession(session);
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExp));
        refreshToken.setRevoked(false);
        refreshTokenRepository.save(refreshToken);

        // Create access token
        String accessToken = jwtUtil.generateToken(user.getUsername(), session.getSessionId(), accessExp);

        return new JwtResponse("Login successful", accessToken, rawRefreshToken);
    }

    // ================= REFRESH =================
//    // FIXED: Accepts (String rawToken, String currentIp, String currentUserAgent)
//    @Transactional
//    public JwtResponse refresh(String rawToken, String currentIp, String currentUserAgent) {
//        String tokenHash = sha256(rawToken);
//
//        RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
//                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token - please login again"));
//
//        // Check if token revoked
//        if (storedToken.isRevoked()) {
//            Session session = storedToken.getSession();
//            refreshTokenRepository.deleteBySession(session);
//            sessionRepository.delete(session);
////            sessionRepository.flush();
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
//                    "Token revoked - session terminated. Please login again.");
//        }
//
//        Session session = storedToken.getSession();
//
//        // Check expiry
//        if (storedToken.getExpiryDate().isBefore(Instant.now())) {
//            refreshTokenRepository.delete(storedToken);
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token expired");
//        }
//
//        if (session.getExpiresAt().isBefore(Instant.now())) {
//            refreshTokenRepository.deleteBySession(session);
//            sessionRepository.delete(session);
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired");
//        }
//
//        // Security checks using passed parameters
//        if (!session.getIpAddress().equals(currentIp)) {
////            storedToken.setRevoked(true);
////            refreshTokenRepository.save(storedToken);
////            refreshTokenRepository.deleteBySession(session);
////            sessionRepository.delete(session);
//////            sessionRepository.flush();
//            // Use TransactionTemplate to commit immediately
//            transactionTemplate.execute(status -> {
//                refreshTokenRepository.deleteBySession(session);
//                sessionRepository.delete(session);
//                sessionRepository.flush();
//                return null;
//            });
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "IP changed - session terminated");
//        }
//
//        if (!session.getUserAgent().equals(currentUserAgent)) {
////            storedToken.setRevoked(true);
////            refreshTokenRepository.save(storedToken);
//            refreshTokenRepository.deleteBySession(session);
//            sessionRepository.delete(session);
////            sessionRepository.flush();
//            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User-Agent changed - session terminated");
//        }
//
//        // Token rotation: Revoke old token, create new one
//        storedToken.setRevoked(true);
//        refreshTokenRepository.save(storedToken);
//
//        // Create new refresh token
//        String newRawToken = generateSecureToken();
//        RefreshToken newToken = new RefreshToken();
//        newToken.setTokenHash(sha256(newRawToken));
//        newToken.setSession(session);
//        newToken.setCreatedAt(Instant.now());
//        newToken.setExpiryDate(Instant.now().plusMillis(refreshExp));
//        newToken.setRevoked(false);
//        refreshTokenRepository.save(newToken);
//
//        // Update session
//        session.setLastActive(Instant.now());
//        session.setExpiresAt(Instant.now().plusMillis(refreshExp));
//        sessionRepository.save(session);
//
//        // Generate new access token
//        String newAccessToken = jwtUtil.generateToken(
//                session.getUser().getUsername(),
//                session.getSessionId(),
//                accessExp
//        );
//
//        return new JwtResponse("Token refreshed", newAccessToken, newRawToken);
//    }


// ================= REFRESH =================
public JwtResponse refresh(String rawToken, String currentIp, String currentUserAgent) {
    String tokenHash = sha256(rawToken);

    // Find the token
    RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token - please login again"));

    // Check if token revoked
    if (storedToken.isRevoked()) {
        Session session = storedToken.getSession();
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                "Token revoked - session terminated. Please login again.");
    }

    Session session = storedToken.getSession();

    // Check token expiry
    if (storedToken.getExpiryDate().isBefore(Instant.now())) {
        transactionTemplate.execute(status -> {
            refreshTokenRepository.delete(storedToken);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token expired");
    }

    // Check session expiry
    if (session.getExpiresAt().isBefore(Instant.now())) {
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired");
    }

    // Check IP address
    if (!session.getIpAddress().equals(currentIp)) {
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "IP changed - session terminated");
    }

    // Check User-Agent
    if (!session.getUserAgent().equals(currentUserAgent)) {
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User-Agent changed - session terminated");
    }

    // Happy path - Token rotation
    return transactionTemplate.execute(status -> {
        // Revoke old token
        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);

        // Create new refresh token
        String newRawToken = generateSecureToken();
        RefreshToken newToken = new RefreshToken();
        newToken.setTokenHash(sha256(newRawToken));
        newToken.setSession(session);
        newToken.setCreatedAt(Instant.now());
        newToken.setExpiryDate(Instant.now().plusMillis(refreshExp));
        newToken.setRevoked(false);
        refreshTokenRepository.save(newToken);

        // Update session
        session.setLastActive(Instant.now());
        session.setExpiresAt(Instant.now().plusMillis(refreshExp));
        sessionRepository.save(session);

        // Generate new access token
        String newAccessToken = jwtUtil.generateToken(
                session.getUser().getUsername(),
                session.getSessionId(),
                accessExp
        );

        return new JwtResponse("Token refreshed", newAccessToken, newRawToken);
    });
}
    // ================= LOGOUT =================
    @Transactional
    public String logout(String sessionId) {
        Session session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found"));

        refreshTokenRepository.deleteBySession(session);
        sessionRepository.delete(session);

        return "Logged out successfully";
    }
}