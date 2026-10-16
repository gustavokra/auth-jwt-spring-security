package com.dev.security.config.accountLock;

import java.time.LocalDateTime;

import org.springframework.stereotype.Service;

import com.dev.security.repository.UserRepository;

@Service
public class LoginAttemptService {
    private static final int MAX_ATTEMPTS = 5;
    private static final int DELAY_START_AT = 3;

    private final UserRepository userRepository;

    public LoginAttemptService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void applyProgressiveDelay(String email) {
        userRepository.findUserByEmail(email).ifPresent(user -> {
            int attempts = user.getFailedLoginAttempts();
            if (attempts >= DELAY_START_AT) {
                long delayMs = attempts * 1000L;
                delayMs = Math.min(delayMs, 10_000L);
                try {
                    Thread.sleep(delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });
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
            }
            userRepository.save(user);
        });
    }
}
