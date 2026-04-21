package com.gauri.generateToken.service;

import com.gauri.generateToken.dto.JwtResponse;
import com.gauri.generateToken.dto.LoginRequest;
import com.gauri.generateToken.dto.RegisterRequest;
import com.gauri.generateToken.entity.RefreshToken;
import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import com.gauri.generateToken.repository.RefreshTokenRepository;
import com.gauri.generateToken.repository.SessionRepository;
import com.gauri.generateToken.repository.UserRepository;
import com.gauri.generateToken.security.JwtUtil;
import lombok.extern.slf4j.Slf4j;
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
import java.util.UUID;

@Service
@Slf4j
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

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 not found", e);
            throw new RuntimeException("SHA-256 not found", e);
        }
    }

    private String generateSecureToken() {
        return UUID.randomUUID() + "." + UUID.randomUUID();
    }

    // ================= REGISTER =================
    public ResponseEntity<?> register(RegisterRequest request) {
        log.info("Registration attempt for username: {}", request.getUsername());

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            log.warn("Registration failed - Username already exists: {}", request.getUsername());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User already exists");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        log.info("User registered successfully: {}", request.getUsername());
        return new ResponseEntity<>(Map.of("message", "User registered successfully"),
                HttpStatus.CREATED);
    }

    // ================= LOGIN =================
    @Transactional
    public JwtResponse login(LoginRequest request, String ipAddress, String userAgent) {
        log.info("Login attempt for user: {} from IP: {}", request.getUsername(), ipAddress);

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(), request.getPassword())
            );
            log.debug("Authentication successful for user: {}", request.getUsername());
        } catch (BadCredentialsException e) {
            log.warn("Login failed - Invalid credentials for user: {} from IP: {}",
                    request.getUsername(), ipAddress);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Invalid username or password");
        }

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    log.error("User not found after successful authentication: {}", request.getUsername());
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not found");
                });

        // Delete old session if exists
        sessionRepository.findByUser(user).ifPresent(oldSession -> {
            log.info("Deleting existing session for user: {}, sessionId: {}",
                    user.getUsername(), oldSession.getSessionId());
            refreshTokenRepository.deleteBySession(oldSession);
            sessionRepository.delete(oldSession);
            sessionRepository.flush();
        });

        // Create new session
        Session session = new Session();
        session.setSessionId(UUID.randomUUID().toString());
        session.setUser(user);
        session.setIpAddress(ipAddress);
        session.setUserAgent(userAgent);
        session.setCreatedAt(Instant.now());
        session.setExpiresAt(Instant.now().plusMillis(refreshExp));
        session.setLastActive(Instant.now());
        sessionRepository.saveAndFlush(session);

        log.debug("Session created for user: {}, sessionId: {}", user.getUsername(), session.getSessionId());

        // Create refresh token
        String rawRefreshToken = generateSecureToken();
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setTokenHash(sha256(rawRefreshToken));
        refreshToken.setSession(session);
        refreshToken.setCreatedAt(Instant.now());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshExp));
        refreshToken.setRevoked(false);
        refreshTokenRepository.save(refreshToken);

        String accessToken = jwtUtil.generateToken(
                user.getUsername(), session.getSessionId(), accessExp);

        log.info("Login successful for user: {} from IP: {}, sessionId: {}",
                user.getUsername(), ipAddress, session.getSessionId());

        return new JwtResponse("Login successful", accessToken, rawRefreshToken);
    }


// ================= REFRESH =================
public JwtResponse refresh(String rawToken, String currentIp, String currentUserAgent) {
    String tokenHash = sha256(rawToken);
    log.info("Refresh token attempt from IP: {}", currentIp);

    // Find the token
    RefreshToken storedToken = refreshTokenRepository.findByTokenHash(tokenHash)
            .orElseThrow(() -> {
                log.warn("Refresh token failed - Token not found from IP: {}", currentIp);
                return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token - please login again");
            });

    Session session = storedToken.getSession();
    String username = session.getUser().getUsername();
    log.debug("Processing refresh token for user: {}, sessionId: {}", username, session.getSessionId());


    // Check if token revoked
    if (storedToken.isRevoked()) {
        log.warn("Refresh token revoked for user: {}, sessionId: {}", username, session.getSessionId());
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                "Token revoked - session terminated. Please login again.");
    }

    // Check token expiry
    if (storedToken.getExpiryDate().isBefore(Instant.now())) {
        log.warn("Refresh token expired for user: {}, sessionId: {}", username, session.getSessionId());
        transactionTemplate.execute(status -> {
            refreshTokenRepository.delete(storedToken);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token expired");
    }

    // Check session expiry
    if (session.getExpiresAt().isBefore(Instant.now())) {
        log.warn("Session expired for user: {}, sessionId: {}", username, session.getSessionId());
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired");
    }

    // Check IP address
    if (!session.getIpAddress().equals(currentIp)) {
        log.warn("IP mismatch for user: {}. Expected: {}, Got: {}",
                username, session.getIpAddress(), currentIp);
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "IP changed - session terminated");
    }

    // Check User-Agent
    if (!session.getUserAgent().equals(currentUserAgent)) {
        log.warn("User-Agent mismatch for user: {}", username);
        transactionTemplate.execute(status -> {
            refreshTokenRepository.deleteBySession(session);
            sessionRepository.delete(session);
            return null;
        });
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User-Agent changed - session terminated");
    }

    //  Token rotation
    log.info("Refresh token successful for user: {}, sessionId: {}", username, session.getSessionId());
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

        log.debug("New tokens generated for user: {}", username);
        return new JwtResponse("Token refreshed", newAccessToken, newRawToken);
    });
}

    // ================= LOGOUT =================
    @Transactional
    public String logout(String sessionId) {
        log.info("Logout attempt for sessionId: {}", sessionId);

        Session session = sessionRepository.findBySessionId(sessionId)
                .orElseThrow(() -> {
                    log.warn("Logout failed - Session not found: {}", sessionId);
                    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found");
                });

        String username = session.getUser().getUsername();
        String ipAddress = session.getIpAddress();

        refreshTokenRepository.deleteBySession(session);
        sessionRepository.delete(session);

        log.info("Logout successful for user: {}, sessionId: {}, IP: {}", username, sessionId, ipAddress);
        return "Logged out successfully";
    }
}