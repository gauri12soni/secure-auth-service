package com.gauri.generateToken.repository;

import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, String> {
//
//    // Find active session by sessionId
//    Optional<Session> findBySessionIdAndRevokedFalse(String sessionId);
//
//    // Get all sessions of a user
//    List<Session> findByUser(User user);
//
//    // Find ACTIVE session for same device
//    Optional<Session> findByUserAndDeviceIdAndRevokedFalse(User user, String deviceId);
//
//
//    // Cleanup expired sessions (optional)
//    List<Session> findByExpiresAtBefore(Instant now);
//
//    Optional<Session> findBySessionIdAndRevokedFalse(String sessionId);
//
//    List<Session> findByUser(User user);
//
//    Optional<Session> findByUserAndRevokedFalse(User user);  // ← ADD THIS
//
//
//    List<Session> findByExpiresAtBefore(Instant now);

    // Get user's session (only one exists)
    Optional<Session> findByUser(User user);

    // Get session by ID (no revoked check needed)
    Optional<Session> findBySessionId(String sessionId);

    // Cleanup expired sessions
    List<Session> findByExpiresAtBefore(Instant now);

    // Delete by user
    void deleteByUser(User user);

//    // ✅ OPTIONAL - Add these for convenience (not required)
//    Optional<Session> findByUserAndRevokedFalse(User user);  // Find only active session
//    Optional<Session> findBySessionIdAndRevokedFalse(String sessionId);



}
