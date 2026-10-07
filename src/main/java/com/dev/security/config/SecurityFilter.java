package com.dev.security.config;

import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class SecurityFilter extends OncePerRequestFilter {

    private final TokenConfig tokenConfig;

    public SecurityFilter(TokenConfig tokenConfig) {
        this.tokenConfig = tokenConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        validateHeaderAndDoFilterInternal(request, response, filterChain);
    }

private void validateHeaderAndDoFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain) throws IOException, ServletException {

    String authorizedHeader = request.getHeader("Authorization");

    if (Strings.isNotEmpty(authorizedHeader) && authorizedHeader.startsWith("Bearer ")) {

        Optional<JWTUserData> userData = retornarUserDetailsDeToken(authorizedHeader);

        if (userData.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Token inválido ou expirado\"}");
        }

        adcUserDetalhesSecurityContext(userData);
    }

    filterChain.doFilter(request, response);
}

    private void adcUserDetalhesSecurityContext(Optional<JWTUserData> optUser) {
        optUser.ifPresent(userData -> {
            Set<GrantedAuthority> authorities = retornarAuthorities(userData.role());

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    userData, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        });
    }

    private Optional<JWTUserData> retornarUserDetailsDeToken(String autorizedHeader) {
        String token = autorizedHeader.replace("Bearer ", "");
        return tokenConfig.validateToken(token);
    }

    private Set<GrantedAuthority> retornarAuthorities(String role) {
        Set<GrantedAuthority> authorities = new HashSet<>();
        if ("ADMIN".equals(role)) {
            authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        } else {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        return authorities;
    }

}
