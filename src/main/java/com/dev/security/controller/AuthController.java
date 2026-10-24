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
import com.dev.security.config.captcha.CaptchaService;
import com.dev.security.config.token.RefreshTokenService;
import com.dev.security.config.token.TokenConfig;
import com.dev.security.dto.request.LoginRequest;
import com.dev.security.dto.request.RefreshRequest;
import com.dev.security.dto.request.RegisterUserRequest;
import com.dev.security.dto.response.LoginResponse;
import com.dev.security.dto.response.RegisterUserResponse;
import com.dev.security.entity.User;
import com.dev.security.enums.UserRole;
import com.dev.security.repository.UserRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenConfig tokenConfig;
    private final LoginAttemptService loginAttemptService;
    private final CaptchaService captchaService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserRepository repo,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            TokenConfig tokenConfig,
            LoginAttemptService loginAttemptService,
            CaptchaService captchaService,
            RefreshTokenService refreshTokenService) {

        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenConfig = tokenConfig;
        this.loginAttemptService = loginAttemptService;
        this.captchaService = captchaService;
        this.refreshTokenService = refreshTokenService;

    }

    @PostMapping(value = "/login", consumes = "application/json")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {

        if (!captchaService.isValid(request.captchaToken())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CAPTCHA inválido ou não resolvido");
        }

        loginAttemptService.applyProgressiveDelay(request.email());

        UsernamePasswordAuthenticationToken userAndPass = new UsernamePasswordAuthenticationToken(request.email(),
                request.password());

        Authentication authentication = authenticationManager.authenticate(userAndPass);

        User user = (User) authentication.getPrincipal();

        String accessToken = tokenConfig.generateAccessToken(user);
        String refreshToken = refreshTokenService.create(user.getId(), user.getEmail());

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshRequest request) {

        RefreshTokenService.RefreshSession session = refreshTokenService
                .find(request.refreshToken())
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh inválido ou expirado"));

        User user = repo.findUserByEmail(session.email())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuário não encontrado"));

        if (!user.isAccountNonLocked()) {
            refreshTokenService.revokeByKey(session.redisKey());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Conta bloqueada");
        }

        refreshTokenService.revokeByKey(session.redisKey());

        String newAccess = tokenConfig.generateAccessToken(user);
        String newRefresh = refreshTokenService.create(user.getId(), user.getEmail());

        return ResponseEntity.ok(new LoginResponse(newAccess, newRefresh));
    }

@PostMapping("/logout")
public ResponseEntity<Void> logout(
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestBody(required = false) RefreshRequest body) {

    if (authorization != null && authorization.startsWith("Bearer ")) {
        tokenConfig.revokeAccessToken(authorization.substring(7).trim());
    }

    if (body != null && body.refreshToken() != null) {
        refreshTokenService.revoke(body.refreshToken());
    }

    return ResponseEntity.noContent().build();
}

    @PostMapping(value = "/register", consumes = "application/json")
    public ResponseEntity<RegisterUserResponse> register(
            @Valid @RequestBody RegisterUserRequest request) {
        User newUser = new User();

        newUser.setName(request.nome());
        if (repo.findUserByEmail(request.email()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email já cadastrado");
        }
        newUser.setEmail(request.email());
        newUser.setPassword(passwordEncoder.encode(request.senha()));
        newUser.setRole(UserRole.USER);

        repo.save(newUser);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterUserResponse(newUser.getName(), newUser.getEmail()));
    }

}
