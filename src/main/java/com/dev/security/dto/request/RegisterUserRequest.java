package com.dev.security.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterUserRequest(
        @NotEmpty(message = "Nome é obrigatório")
        String nome,

        @Email
        @NotEmpty(message = "Email é obrigatório")
        String email,

        @NotEmpty(message = "Senha é obrigatória")
        @Size(min = 8, message = "Senha deve ter no mínimo 8 caracteres")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#._-]).{8,}$",
                message = "Senha deve ter maiúscula, minúscula, número e caractere especial"
        )
        String senha
) {

}
