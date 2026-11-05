package com.dev.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.dev.security.config.accountLock.LoginAttemptService;
import com.dev.security.config.audit.SecurityAuditLogger;
import com.dev.security.config.captcha.CaptchaService;
import com.dev.security.config.token.RefreshTokenService;
import com.dev.security.config.token.TokenConfig;
import com.dev.security.dto.request.LoginRequest;
import com.dev.security.dto.request.RefreshRequest;
import com.dev.security.dto.request.RegisterUserRequest;
import com.dev.security.dto.response.LoginResponse;
import com.dev.security.dto.response.MessageResponse;
import com.dev.security.entity.User;
import com.dev.security.enums.UserRole;
import com.dev.security.repository.UserRepository;
import com.dev.security.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final TokenConfig tokenConfig;
    private final RefreshTokenService refreshTokenService;
    private final SecurityAuditLogger audit;

    private final AuthService service;

    public AuthController(UserRepository repo,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            TokenConfig tokenConfig,
            LoginAttemptService loginAttemptService,
            CaptchaService captchaService,
            RefreshTokenService refreshTokenService,
            SecurityAuditLogger audit,
            AuthService service) {

        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
        this.tokenConfig = tokenConfig;
        this.refreshTokenService = refreshTokenService;
        this.audit = audit;
        this.service = service;
    }

    @PostMapping(value = "/login", consumes = "application/json")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        return ResponseEntity.ok(service.login(request, httpRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {

        return ResponseEntity.ok(service.refresh(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) RefreshRequest body) {

        String accessToken = null;

        if (authorization != null && authorization.startsWith("Bearer ")) {
            accessToken = authorization.substring(7).trim();
            tokenConfig.revokeAccessToken(accessToken);
        }

        if (body != null && body.refreshToken() != null) {
            refreshTokenService.revoke(body.refreshToken());
        }

        String email = tokenConfig.extractEmail(accessToken).orElse("-");
        audit.logout(email);

        return ResponseEntity.noContent().build();
    }

    @PostMapping(value = "/register", consumes = "application/json")
    public ResponseEntity<MessageResponse> register(
            @Valid @RequestBody RegisterUserRequest request) {

        final String generic = "Se os dados forem válidos, a conta foi criada. Faça login.";

        if (repo.findUserByEmail(request.email()).isEmpty()) {
            User newUser = new User();
            newUser.setName(request.nome());
            newUser.setEmail(request.email());
            newUser.setPassword(passwordEncoder.encode(request.senha()));
            newUser.setRole(UserRole.USER);
            repo.save(newUser);
        }

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new MessageResponse(generic));
    }

    private String clientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf == null || xf.isBlank()) {
            return request.getRemoteAddr();
        }
        return xf.split(",")[0].trim();
    }

}
