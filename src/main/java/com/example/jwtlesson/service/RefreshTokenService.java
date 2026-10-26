
package com.example.jwtlesson.service;

import com.example.jwtlesson.entity.RefreshToken;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repository;

    private static final SecureRandom RANDOM = new SecureRandom();

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    @Transactional
    public String create(User user) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);

        String rawToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setHashToken(hash(rawToken));
        token.setExpiration(
                Instant.now().plusMillis(refreshExpirationMs)
        );

        repository.save(token);

        return rawToken;
    }

    @Transactional
    public Rotation rotate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw invalidToken();
        }

        RefreshToken oldToken = repository
                .findForRotation(hash(rawToken))
                .orElseThrow(this::invalidToken);

        if (oldToken.isRevoked()
                || !oldToken.getExpiration().isAfter(Instant.now())
                || !oldToken.getUser().isEnabled()) {
            throw invalidToken();
        }

        oldToken.setRevoked(true);

        User user = oldToken.getUser();
        String newToken = create(user);

        return new Rotation(user.getUsername(), newToken);
    }

    public record Rotation(
            String username,
            String refreshToken) {}

    private ResponseStatusException invalidToken() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Invalid or expired refresh token"
        );
    }

    private String hash(String value) {
        try {
            byte[] digest = MessageDigest
                    .getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
