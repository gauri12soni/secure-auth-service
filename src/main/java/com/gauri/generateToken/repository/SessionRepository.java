package com.gauri.generateToken.repository;

import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface SessionRepository extends JpaRepository<Session, String> {

    // Get user's session (only one exists)
    Optional<Session> findByUser(User user);

    // Get session by ID (no revoked check needed)
    Optional<Session> findBySessionId(String sessionId);

    // Cleanup expired sessions
    List<Session> findByExpiresAtBefore(Instant now);

    // Delete by user
    void deleteByUser(User user);




}
