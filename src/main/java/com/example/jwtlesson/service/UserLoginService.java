package com.example.jwtlesson.service;

import com.example.jwtlesson.dto.LoginRequest;
import com.example.jwtlesson.dto.LoginResponse;
import com.example.jwtlesson.dto.RegisterRequest;
import com.example.jwtlesson.dto.UserResponse;
import com.example.jwtlesson.entity.Role;
import com.example.jwtlesson.entity.RoleName;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.exception.UsernameTakenException;
import com.example.jwtlesson.repository.RoleRepository;
import com.example.jwtlesson.repository.UserRepository;
import com.example.jwtlesson.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.jwtlesson.security.CustomUserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserLoginService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    private final RefreshTokenService refreshTokenService;
    private final CustomUserDetailsService userDetailsService;



    @Transactional
    public LoginResponse login(LoginRequest request) {
        Authentication authentication =
                authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                request.username(),
                                request.password()
                        )
                );

        UserDetails userDetails =
                (UserDetails) authentication.getPrincipal();

        User user = userRepository
                .findByUsername(userDetails.getUsername())
                .orElseThrow();

        String accessToken = jwtUtil.generateToken(userDetails);
        String refreshToken = refreshTokenService.create(user);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new LoginResponse(
                accessToken,
                "Bearer",
                jwtUtil.getExpirationMs(),
                userDetails.getUsername(),
                roles,
                refreshToken
        );
    }


    /** New users always get ROLE_USER only. Admins are never created through this endpoint. */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameTakenException(request.username());
        }

        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("ROLE_USER missing - did DataInitializer run?"));

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        return UserResponse.from(userRepository.save(user));


    }

    public LoginResponse refresh(String oldRefreshToken) {
        RefreshTokenService.Rotation rotation =
                refreshTokenService.rotate(oldRefreshToken);

        UserDetails userDetails = userDetailsService
                .loadUserByUsername(rotation.username());

        String newAccessToken = jwtUtil.generateToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new LoginResponse(
                newAccessToken,
                "Bearer",
                jwtUtil.getExpirationMs(),
                userDetails.getUsername(),
                roles,
                rotation.refreshToken()
        );
    }

}