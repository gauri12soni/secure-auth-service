package com.gauri.generateToken.repository;

import com.gauri.generateToken.entity.RefreshToken;
import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {


    Optional<RefreshToken> findByTokenHash(String tokenHash);
    List<RefreshToken> findBySession(Session session);
    void deleteBySession(Session session);

    // Add this method
    void deleteBySessionAndRevokedTrue(Session session);



}


