package com.example.jwtlesson.repository;

import com.example.jwtlesson.entity.RefreshToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT r FROM RefreshToken r
        JOIN FETCH r.user
        WHERE r.HashToken = :hash
    """)

    Optional<RefreshToken> findForRotation(
            @Param("hash") String hash);

}
