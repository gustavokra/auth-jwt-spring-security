package com.dev.security.config.captcha;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

@Service
public class CaptchaService {

    private final String secret;
    private final RestClient restClient;

    public CaptchaService(@Value("${recaptcha.secret}") String secret) {
        this.secret = secret;
        this.restClient = RestClient.create();
    }

    public boolean isValid(String captchaToken) {
        if (captchaToken == null || captchaToken.isBlank()) {
            return false;
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("secret", secret);
        form.add("response", captchaToken);

        @SuppressWarnings("unchecked")
        Map<String, Object> body = restClient.post()
                .uri("https://www.google.com/recaptcha/api/siteverify")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return body != null && Boolean.TRUE.equals(body.get("success"));
    }
}