package com.dev.security.service;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.dev.security.config.accountLock.LoginAttemptService;
import com.dev.security.config.audit.SecurityAuditLogger;
import com.dev.security.config.captcha.CaptchaService;
import com.dev.security.config.token.RefreshTokenService;
import com.dev.security.config.token.TokenConfig;
import com.dev.security.dto.request.LoginRequest;
import com.dev.security.dto.response.LoginResponse;
import com.dev.security.entity.User;
import com.dev.security.repository.UserRepository;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class AuthService {
    
    private final UserRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final TokenConfig tokenConfig;
    private final CaptchaService captchaService;
    private final RefreshTokenService refreshTokenService;
    private final SecurityAuditLogger audit;

    public AuthService(UserRepository repo,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            TokenConfig tokenConfig,
            LoginAttemptService loginAttemptService,
            CaptchaService captchaService,
            RefreshTokenService refreshTokenService,
            SecurityAuditLogger audit) {

        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.tokenConfig = tokenConfig;
        this.captchaService = captchaService;
        this.refreshTokenService = refreshTokenService;
        this.audit = audit;
    }

    public LoginResponse login(LoginRequest request,
            HttpServletRequest httpRequest) {
         if (!captchaService.isValid(request.captchaToken())) {
            audit.captchaInvalid(request.email(), clientIp(httpRequest));
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "CAPTCHA inválido ou não resolvido");
        }

        UsernamePasswordAuthenticationToken userAndPass = new UsernamePasswordAuthenticationToken(request.email(),
                request.password());

        Authentication authentication = authenticationManager.authenticate(userAndPass);

        User user = (User) authentication.getPrincipal();

        String accessToken = tokenConfig.generateAccessToken(user);
        String refreshToken = refreshTokenService.create(user.getId(), user.getEmail());

        return new LoginResponse(accessToken, refreshToken);
    }

    private String clientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf == null || xf.isBlank()) {
            return request.getRemoteAddr();
        }
        return xf.split(",")[0].trim();
    }

}
