package com.dev.security.config.token;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RefreshTokenService {

    private static final String KEY_PREFIX = "refresh:";
    private static final Duration TTL = Duration.ofDays(7);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final StringRedisTemplate redis;

    public RefreshTokenService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /** Gera token opaco, grava hash no Redis, devolve o valor em claro (só uma vez ao cliente). */
    public String create(Long userId, String email) {
        String rawToken = generateRawToken();
        String key = KEY_PREFIX + sha256(rawToken);

        String value = userId + ":" + email;
        redis.opsForValue().set(key, value, TTL);

        return rawToken;
    }

    /** Valida o token opaco. Se ok, devolve userId e email. */
    public Optional<RefreshSession> find(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Optional.empty();
        }
        String key = KEY_PREFIX + sha256(rawToken);
        String value = redis.opsForValue().get(key);
        if (value == null) {
            return Optional.empty();
        }
        String[] parts = value.split(":", 2);
        if (parts.length != 2) {
            return Optional.empty();
        }
        return Optional.of(new RefreshSession(Long.parseLong(parts[0]), parts[1], key));
    }

    /** Remove o refresh (logout ou rotação). */
    public void revoke(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        redis.delete(KEY_PREFIX + sha256(rawToken));
    }

    public void revokeByKey(String redisKey) {
        redis.delete(redisKey);
    }

    private String generateRawToken() {
        byte[] bytes = new byte[32]; // 256 bits
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private String sha256(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(dig);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 não disponível", e);
        }
    }

    public record RefreshSession(Long userId, String email, String redisKey) {}
}