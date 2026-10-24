package com.dev.security.config.token;

import lombok.Builder;

@Builder
public record JWTUserData(Long userId, String email, String role) {

}
