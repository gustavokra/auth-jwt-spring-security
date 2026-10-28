package com.dev.security.config.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SecurityAuditLogger {

    private static final Logger log = LoggerFactory.getLogger("SECURITY_AUDIT");

    public void loginSuccess(String email, String ip) {
        log.info("event=LOGIN_SUCCESS email={} ip={}", email, ip);
    }

    public void loginFailure(String email, String ip, String reason) {
        log.warn("event=LOGIN_FAILURE email={} ip={} reason={}", email, ip, reason);
    }

    public void accountLocked(String email, int attempts) {
        log.warn("event=ACCOUNT_LOCKED email={} failedAttempts={}", email, attempts);
    }

    public void captchaInvalid(String email, String ip) {
        log.warn("event=CAPTCHA_INVALID email={} ip={}", email, ip);
    }

    public void rateLimited(String ip, String path) {
        log.warn("event=RATE_LIMITED ip={} path={}", ip, path);
    }

    public void refreshSuccess(String email) {
        log.info("event=REFRESH_SUCCESS email={}", email);
    }

    public void refreshFailure(String reason) {
        log.warn("event=REFRESH_FAILURE reason={}", reason);
    }

    public void logout(String emailOrUnknown) {
        log.info("event=LOGOUT subject={}", emailOrUnknown);
    }
}