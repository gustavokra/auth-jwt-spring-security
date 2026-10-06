package com.dev.security.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record LoginRequest(@Email @NotEmpty(message = "Email é obrigatório") String email,
                @NotEmpty(message = "Senha é obrigatória") String password) {

}
