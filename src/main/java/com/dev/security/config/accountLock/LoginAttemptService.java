package com.dev.security.config.accountLock;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.dev.security.config.audit.SecurityAuditLogger;
import com.dev.security.entity.User;
import com.dev.security.repository.UserRepository;

@Service
public class LoginAttemptService {
    private static final int MAX_ATTEMPTS = 5;

    private final UserRepository userRepository;
    private final SecurityAuditLogger audit;

    public LoginAttemptService(UserRepository userRepository,
            SecurityAuditLogger audit) {
        this.userRepository = userRepository;
        this.audit = audit;
    }

    public void loginSucceeded(String email) {
        userRepository.findUserByEmail(email).ifPresent(user -> {
            user.setFailedLoginAttempts(0);
            user.setAccountNonLocked(true);
            user.setLockTime(null);
            userRepository.save(user);
        });
    }

    public void loginFailed(String email) {
        userRepository.findUserByEmail(email).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= MAX_ATTEMPTS) {
                user.setAccountNonLocked(false);
                user.setLockTime(LocalDateTime.now());
                audit.accountLocked(email, attempts);
            }
            userRepository.save(user);
        });
    }

    public void unlockIfExpired(User user) {
        if (user.isLockExpired()) {
            user.setAccountNonLocked(true);
            user.setFailedLoginAttempts(0);
            user.setLockTime(null);
            userRepository.save(user);
        }
    }

}
