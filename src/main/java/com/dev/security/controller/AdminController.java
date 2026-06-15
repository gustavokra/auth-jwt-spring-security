package com.dev.security.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.dev.security.dto.request.RegisterUserRequest;
import com.dev.security.dto.response.RegisterUserResponse;
import com.dev.security.entity.User;
import com.dev.security.enums.UserRole;
import com.dev.security.repository.UserRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("api/v1/admin")
public class AdminController {

    private UserRepository repo;
    private PasswordEncoder passwordEncoder;

    public AdminController(UserRepository repo, PasswordEncoder passwordEncoder) {
        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterUserResponse> criarAdmin(
        @Valid @RequestBody RegisterUserRequest request) {

        User newAdmin = new User();

        newAdmin.setName(request.nome());
        newAdmin.setEmail(request.email());
        newAdmin.setPassword(passwordEncoder.encode(request.senha()));
        newAdmin.setRole(UserRole.ADMIN);

        repo.save(newAdmin);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new RegisterUserResponse(newAdmin.getName(), newAdmin.getEmail()));
    }


    @GetMapping("/users")
    public ResponseEntity<?> listarUsuarios() {
        return ResponseEntity.ok().build();
    }

}
