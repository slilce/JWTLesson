package com.example.jwtlesson;

import com.example.jwtlesson.entity.Role;
import com.example.jwtlesson.entity.RoleName;
import com.example.jwtlesson.entity.User;
import com.example.jwtlesson.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:jwt_lesson_test;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class JwtLessonApplicationTests {

    private static final String ADMIN_PASSWORD = UUID.randomUUID().toString();
    private static final String USER_PASSWORD = UUID.randomUUID().toString();

    @DynamicPropertySource
    static void seedPasswords(DynamicPropertyRegistry registry) {
        registry.add("app.init.admin.password", () -> ADMIN_PASSWORD);
        registry.add("app.init.user.password", () -> USER_PASSWORD);
    }

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void createsInitialUsersWithHashedPasswordsAndExpectedRoles() {
        User admin = userRepository.findByUsername("admin").orElseThrow();
        User user = userRepository.findByUsername("user").orElseThrow();

        assertEquals(Set.of(RoleName.ROLE_ADMIN, RoleName.ROLE_USER), roleNames(admin));
        assertEquals(Set.of(RoleName.ROLE_USER), roleNames(user));
        assertTrue(passwordEncoder.matches(ADMIN_PASSWORD, admin.getPassword()));
        assertTrue(passwordEncoder.matches(USER_PASSWORD, user.getPassword()));
    }

    private static Set<RoleName> roleNames(User user) {
        return user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());
    }
}