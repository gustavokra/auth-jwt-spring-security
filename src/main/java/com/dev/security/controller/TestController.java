package com.dev.security.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    
    @GetMapping
    public String teste() {

        String salt = KeyGenerators.string().generateKey();
        Encryptors.stronger("password", salt);
        Encryptors.text("password", salt);
        
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(6);
        String result = encoder.encode("senha");

        if(encoder.matches("senha", result)) {
            System.out.println("igual");
        }

        return "Testando segurança";
    }

}
