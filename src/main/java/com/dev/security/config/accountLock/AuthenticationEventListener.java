package com.dev.security.config.accountLock;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.dev.security.config.audit.SecurityAuditLogger;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class AuthenticationEventListener {

    private final LoginAttemptService loginAttemptService;
    private final SecurityAuditLogger audit;

    public AuthenticationEventListener(LoginAttemptService loginAttemptService,
            SecurityAuditLogger audit) {
        this.loginAttemptService = loginAttemptService;
        this.audit = audit;
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        String email = event.getAuthentication().getName();
        loginAttemptService.loginSucceeded(email);
        audit.loginSuccess(email, currentIp()); // ver nota sobre IP abaixo
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        String email = String.valueOf(event.getAuthentication().getPrincipal());
        loginAttemptService.loginFailed(email);
        audit.loginFailure(email, currentIp(), "bad_credentials");
    }

    // opcional: conta bloqueada
    @EventListener
    public void onLocked(org.springframework.security.authentication.event.AuthenticationFailureLockedEvent event) {
        String email = String.valueOf(event.getAuthentication().getPrincipal());
        audit.loginFailure(email, currentIp(), "account_locked");
    }

    private String currentIp() {
        try {
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return "-";
            }
            HttpServletRequest request = attrs.getRequest();
            String xf = request.getHeader("X-Forwarded-For");
            if (xf == null || xf.isBlank()) {
                return request.getRemoteAddr();
            }
            return xf.split(",")[0].trim();
        } catch (Exception e) {
            return "-";
        }
    }
}