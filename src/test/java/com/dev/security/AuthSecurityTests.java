package com.dev.security;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.dev.security.config.captcha.CaptchaService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
class AuthSecurityTests {

    @Autowired
    private WebApplicationContext context;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @MockitoBean
    private CaptchaService captchaService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        when(captchaService.isValid(anyString())).thenReturn(true);
    }

    @Test
    void protectedRoute_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/admin/register")) // ajuste para uma rota GET autenticada se tiver
                .andExpect(status().isUnauthorized());
    }

    // Se não tiver GET protegido, use POST admin sem token:
    @Test
    void adminRegister_withoutToken_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/admin/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"nome":"Admin","email":"a@test.com","senha":"senha12345"}
                        """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withInvalidCaptcha_returns400() throws Exception {
        when(captchaService.isValid(anyString())).thenReturn(false);

        mockMvc.perform(post("/api/v1/auth/login")
                .header("X-Forwarded-For", "203.0.113.50")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"user@test.com","password":"senha12345","captchaToken":"x"}
                        """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void register_thenLogin_returnsTokens() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"nome":"User","email":"user@test.com","senha":"senha12345"}
                        """))
                .andExpect(status().isCreated());

        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"user@test.com","password":"senha12345","captchaToken":"ok"}
                        """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        JsonNode body = objectMapper.readTree(login.getResponse().getContentAsString());
        String access = body.get("accessToken").asText();

        // admin sem role ADMIN → 403
        mockMvc.perform(post("/api/v1/admin/register")
                .header("Authorization", "Bearer " + access)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"nome":"Outro","email":"outro@test.com","senha":"senha12345"}
                        """))
                .andExpect(status().isForbidden());
    }

    @Test
    void refresh_withInvalidToken_returns401() throws Exception {
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"refreshToken":"token-invalido"}
                        """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_thenAccessTokenRejected() throws Exception {
        // register + login
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"nome":"User2","email":"user2@test.com","senha":"senha12345"}
                        """))
                .andExpect(status().isCreated());

        MvcResult login = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"user2@test.com","password":"senha12345","captchaToken":"ok"}
                        """))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(login.getResponse().getContentAsString());
        String access = body.get("accessToken").asText();
        String refresh = body.get("refreshToken").asText();

        mockMvc.perform(post("/api/v1/auth/logout")
                .header("Authorization", "Bearer " + access)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isNoContent());

        // access na denylist → 401 em rota protegida
        mockMvc.perform(post("/api/v1/admin/register")
                .header("Authorization", "Bearer " + access)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"nome":"X","email":"x@test.com","senha":"senha12345"}
                        """))
                .andExpect(status().isUnauthorized());
    }
}