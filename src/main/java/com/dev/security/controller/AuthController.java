package com.dev.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dev.security.dto.request.LoginRequest;
import com.dev.security.dto.request.RefreshRequest;
import com.dev.security.dto.request.RegisterUserRequest;
import com.dev.security.dto.response.LoginResponse;
import com.dev.security.dto.response.MessageResponse;
import com.dev.security.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final AuthService service;

    public AuthController(AuthService service) {
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

        return service.logout(authorization, body);
    }

    @PostMapping(value = "/register", consumes = "application/json")
    public ResponseEntity<MessageResponse> register(
            @Valid @RequestBody RegisterUserRequest request) {

        return service.register(request);
    }

}
