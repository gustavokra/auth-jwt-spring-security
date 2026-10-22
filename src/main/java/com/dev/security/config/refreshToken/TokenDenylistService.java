package com.dev.security.config.refreshToken;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class TokenDenylistService {

    private static final String PREFIX = "denylist:";

    private final StringRedisTemplate redis;

    public TokenDenylistService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank()) {
            return;
        }
        long ttlSeconds = Duration.between(Instant.now(), expiresAt).getSeconds();
        if (ttlSeconds <= 0) {
            return; // já expirou; não precisa guardar
        }
        redis.opsForValue().set(PREFIX + jti, "1", ttlSeconds, TimeUnit.SECONDS);
    }

    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}