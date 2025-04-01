package com.ease.security.config.security;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * LoginFilterConfig class is a filter that intercepts HTTP requests and performs authentication checks.
 * It extends the OncePerRequestFilter class to ensure that the filter is executed only once per request.
 * The doFilterInternal method is overridden to implement the filtering logic.
 */

 @Slf4j
public class LoginFilterConfig extends OncePerRequestFilter{

    private static final RequestMatcher REQUESTMATCHER = new AntPathRequestMatcher("/signin", "POST");
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String BASIC_AUTH = "Basic";

    private final JJWTTokenProvider jjwtTokenProvider;

    private final AuthenticationManager authenticationManager;

    public LoginFilterConfig(JJWTTokenProvider jjwtTokenProvider, AuthenticationManager authenticationManager) {
        this.jjwtTokenProvider = jjwtTokenProvider;
        this.authenticationManager = authenticationManager;
    }

   
    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        if(!REQUESTMATCHER.matches(request)){
            filterChain.doFilter(request, response);
            return;
        }

        UsernamePasswordAuthenticationToken usernamePasswordAuthnentication = null;
        
        if(StringUtils.hasText(request.getParameter(USERNAME)) && StringUtils.hasText(request.getParameter(PASSWORD))){
            usernamePasswordAuthnentication = new UsernamePasswordAuthenticationToken(request.getParameter(USERNAME), request.getParameter(PASSWORD));
        }

        if(usernamePasswordAuthnentication == null){
            usernamePasswordAuthnentication = getUsernamePasswordAuthenticationFromBasicAuth(request);
        }
        if(usernamePasswordAuthnentication == null){
            log.error("Invalid authentication token");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid authentication token");
            return;
        }
        try {
            Authentication authenticaion = authenticationManager.authenticate(usernamePasswordAuthnentication);
            if(authenticaion == null){
                log.error("Invalid Creadential provided");
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Creadential provided");
                return;
            }
            SecurityContextHolder.getContext().setAuthentication(authenticaion);
            String token = jjwtTokenProvider.generateJwtToken(authenticaion.getPrincipal().toString());
            response.setHeader("Authorization", "Bearer " + token);
            response.setHeader("Access-Control-Expose-Headers", "Authorization");
            
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            log.error("Authentication failed", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
            return;
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationFromBasicAuth(HttpServletRequest request){
        UsernamePasswordAuthenticationToken usernamePasswordAuthnentication = null;
        String authrization = request.getHeader(AUTHORIZATION);

        if(authrization == null){
            return null;
        }
        authrization.trim();
        if(!authrization.startsWith(BASIC_AUTH)){
            log.error("Unsoported Authentication Type");
        }

        if(authrization.equals(BASIC_AUTH)){
            log.error("Basic auth or creadential is not provided");
        }

        byte[] basicAuthDecodedByte = authrization.substring(6).trim().getBytes();
        byte[] decoder;

        try {
            decoder = Base64.getDecoder().decode(basicAuthDecodedByte);
        } catch (IllegalArgumentException e) {
            log.error("Failed to decode Basic authentication teoken", e);
            return null;
        }
        String basicAuthDecoded = new String(decoder, StandardCharsets.UTF_8);
        
        if(!StringUtils.hasText(basicAuthDecoded)){
            log.error("Failed to decode Basic authentication token");
            return null;
        }

        String[] basicAuthDecodedArray = basicAuthDecoded.split(":");

        if(basicAuthDecodedArray.length != 2){
            log.error("Invalid Basic authentication token");
            return null;
        }
        String username = basicAuthDecodedArray[0];
        String password = basicAuthDecodedArray[1];
        usernamePasswordAuthnentication = new UsernamePasswordAuthenticationToken(username, password);
        return usernamePasswordAuthnentication;
    }

    @Override
    public boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // return !REQUESTMATCHER.matches(request);
        return !request.getServletPath().equals("/signin");
    }

}
