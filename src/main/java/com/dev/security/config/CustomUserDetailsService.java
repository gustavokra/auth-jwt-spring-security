package com.dev.security.config;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.dev.security.config.accountLock.LoginAttemptService;
import com.dev.security.entity.User;
import com.dev.security.repository.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository repo;
    private final LoginAttemptService loginAttemptService;

    public CustomUserDetailsService(UserRepository repo,
            LoginAttemptService loginAttemptService) {
        this.repo = repo;
        this.loginAttemptService = loginAttemptService;
    }

    /*
     * Quando authenticationManager.authenticate(userAndPass) é executado,
     * o Spring delega a autenticação para um AuthenticationProvider
     * (normalmente DaoAuthenticationProvider).
     *
     * O DaoAuthenticationProvider utiliza o bean UserDetailsService
     * configurado na aplicação e chama loadUserByUsername().
     *
     * Por isso, durante o processo de login, a execução chega neste método.
     * Aqui buscamos o usuário no banco e retornamos um objeto UserDetails.
     * 
     * O AuthenticationManager delega para o ProviderManager, que usa o
     * DaoAuthenticationProvider, que chama seu UserDetailsService e depois o
     * PasswordEncoder.
     */
    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repo.findUserByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username));

        loginAttemptService.unlockIfExpired(user);

        return user;
    }

}
