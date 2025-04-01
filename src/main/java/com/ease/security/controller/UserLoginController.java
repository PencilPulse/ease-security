package com.ease.security.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;
import com.ease.security.service.UserAuthDetailService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;


@RestController
@Slf4j
public class UserLoginController {

    @Autowired
    private UserAuthDetailService userAuthDetailService;

    @Autowired
    JJWTTokenProvider jjwtTokenProvider;

 
    @PostMapping("/signin")
    public ResponseEntity<Map<String, String>> login(HttpServletRequest request) {

        String authHeader = request.getHeader("Authorization");
        log.info("Authorization header: {}", authHeader);
        String  username  = SecurityContextHolder.getContext().getAuthentication().getName();
        log.info("Username: {}", username);
        String token = jjwtTokenProvider.generateJwtToken(username);

        return ResponseEntity.ok(Map.of("JWT_TOKEN", token));
    }
}
