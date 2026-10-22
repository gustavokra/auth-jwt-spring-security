package com.dev.security.config;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.dev.security.config.refreshToken.TokenDenylistService;
import com.dev.security.entity.User;

@Component
public class TokenConfig {

    @Value("${api.security.token.secret}")
    private String secret;

    private final TokenDenylistService denylistService;

    public TokenConfig(TokenDenylistService denylistService) {
        this.denylistService = denylistService;
    }

    public String generateAccessToken(User user) {
        Algorithm algorith = Algorithm.HMAC256(secret);
        Instant now = Instant.now();
        String jti = UUID.randomUUID().toString();

        return JWT.create()
                .withJWTId(jti)
                .withClaim("userId", user.getId())
                .withClaim("role", user.getRole().name())
                .withClaim("type", "access")
                .withIssuer("security-api")
                .withSubject(user.getEmail())
                .withIssuedAt(now)
                .withExpiresAt(now.plus(15, ChronoUnit.MINUTES))
                .sign(algorith);
    }

    public Optional<JWTUserData> validateToken(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);

            DecodedJWT decoded = JWT.require(algorithm)
                    .withIssuer("security-api")
                    .build()
                    .verify(token);

            // recusa se estiver na denylist (logout)
            String jti = decoded.getId();
            if (denylistService.isRevoked(jti)) {
                return Optional.empty();
            }

            // opcional: só aceitar access
            String type = decoded.getClaim("type").asString();
            if (type != null && !"access".equals(type)) {
                return Optional.empty();
            }

            return Optional.of(JWTUserData.builder()
                    .userId(decoded.getClaim("userId").asLong())
                    .email(decoded.getSubject())
                    .role(decoded.getClaim("role").asString())
                    .build());

        } catch (JWTVerificationException ex) {
            return Optional.empty();
        }
    }

    /**
     * Coloca o access token na denylist até a data de expiração original.
     * Usa decode (sem validar assinatura de novo) só para ler jti e exp;
     * se quiser ser mais rígido, valide com verify antes.
     */
    public void revokeAccessToken(String token) {
        if (token == null || token.isBlank()) {
            return;
        }
        try {
            // verify garante que só revogamos token nosso/válido
            Algorithm algorithm = Algorithm.HMAC256(secret);
            DecodedJWT decoded = JWT.require(algorithm)
                    .withIssuer("security-api")
                    .build()
                    .verify(token);

            String jti = decoded.getId();
            Instant expiresAt = decoded.getExpiresAt().toInstant();
            denylistService.revoke(jti, expiresAt);

        } catch (JWTVerificationException ex) {
            // token inválido/expirado: tenta pelo menos ler jti/exp sem verify
            try {
                DecodedJWT decoded = JWT.decode(token);
                String jti = decoded.getId();
                if (jti != null && decoded.getExpiresAt() != null) {
                    denylistService.revoke(jti, decoded.getExpiresAt().toInstant());
                }
            } catch (JWTDecodeException ignored) {
                // token malformado — nada a fazer
            }
        }
    }

}
