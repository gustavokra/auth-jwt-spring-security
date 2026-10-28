package com.dev.security.config.rateLimiting;

import java.io.IOException;
import java.time.Duration;
import java.util.function.Supplier;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.dev.security.config.audit.SecurityAuditLogger;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private final ProxyManager<String> proxyManager;
    private final Supplier<BucketConfiguration> configSupplier;
    private final SecurityAuditLogger audit;

    public RateLimitFilter(ProxyManager<String> proxyManager, SecurityAuditLogger audit) {
        this.proxyManager = proxyManager;
        this.audit = audit;
        this.configSupplier = () -> BucketConfiguration.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(5)
                        .refillGreedy(5, Duration.ofMinutes(1))
                        .build())
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path.equals("/api/v1/auth/login") || path.equals("/api/v1/auth/register")) {
            String ip = getClientIP(request);

            // bucket compartilhado no Redis, chave = IP
            Bucket bucket = proxyManager.builder().build(ip, configSupplier);

            if (!bucket.tryConsume(1)) {
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                response.setContentType("application/json");
                response.getWriter().write("""
                        {"error": "Muitas tentativas. Tente novamente em alguns minutos."}
                        """);

                audit.rateLimited(ip, path);
                
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}