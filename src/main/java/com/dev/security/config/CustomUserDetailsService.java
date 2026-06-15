package com.dev.security.config;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.dev.security.repository.UserRepository;
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository repo;

    public CustomUserDetailsService(UserRepository repo) {
        this.repo = repo;
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
     * O AuthenticationManager delega para o ProviderManager, que usa o DaoAuthenticationProvider, que chama seu UserDetailsService e depois o PasswordEncoder.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repo.findUserByEmail(username).orElseThrow(() -> new UsernameNotFoundException(username));
    }
    
}
