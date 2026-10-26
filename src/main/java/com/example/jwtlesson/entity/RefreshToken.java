package com.example.jwtlesson.entity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(nullable = false, name = "user_id")
    private User user;

    @Column(nullable = false, unique = true, length = 64)
    private String HashToken;

    @Column(nullable = false)
    private Instant Expiration;

    @Column(nullable = false)
    private boolean Revoked;

}
