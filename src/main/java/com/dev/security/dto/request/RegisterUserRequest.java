package com.dev.security.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

public record RegisterUserRequest(
                @NotEmpty(message = "Nome é obrigatório") String nome,
                @Email @NotEmpty(message = "Email é obrigatório") String email,
                @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres") @NotEmpty(message = "Senha é obrigatório") String senha) {

}
