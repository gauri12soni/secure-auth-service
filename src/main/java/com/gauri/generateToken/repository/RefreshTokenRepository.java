package com.gauri.generateToken.repository;

import com.gauri.generateToken.entity.RefreshToken;
import com.gauri.generateToken.entity.Session;
import com.gauri.generateToken.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

//    //  Get token by session (used in logout / cleanup)
//    Optional<RefreshToken> findBySession(Session session);
//
//    Optional<RefreshToken> findByTokenId(UUID tokenId);
//
//    //  Delete tokens for a session
//    void deleteBySession(Session session);
//
//
//    //  Used in refresh (since token is hashed)
//    List<RefreshToken> findByRevokedFalse();

//
//    List<RefreshToken> findBySession(Session session);  // ← Changed Optional to List
//
//    Optional<RefreshToken> findByTokenHash(String tokenHash);  // ← Changed from findByTokenId
//
//    void deleteBySession(Session session);

    Optional<RefreshToken> findByTokenHash(String tokenHash);
    List<RefreshToken> findBySession(Session session);
    void deleteBySession(Session session);

    // Add this method
    void deleteBySessionAndRevokedTrue(Session session);



}


