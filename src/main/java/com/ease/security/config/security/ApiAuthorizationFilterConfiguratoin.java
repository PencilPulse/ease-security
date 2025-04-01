package com.ease.security.config.security;

import java.io.IOException;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ApiAuthorizationFilterConfiguratoin extends OncePerRequestFilter {

    private static final RequestMatcher REQUESTMATCHER = new NegatedRequestMatcher(new OrRequestMatcher(Arrays.asList(
            new AntPathRequestMatcher("/signin", "POST"), new AntPathRequestMatcher("/swagger-ui/**"),
            new AntPathRequestMatcher("/v3/api-docs/**"), new AntPathRequestMatcher("/swagger-resources/**"))));

    @Autowired
    private JJWTTokenProvider jwtTokenProvider;

    public ApiAuthorizationFilterConfiguratoin(JJWTTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
       log.info("Inside ApiAuthorizationFilterConfiguratoin");
        String authHeader = request.getHeader("Authorization");
        String jwtToken = null;
        String paylod = null;
        String username = null;
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                jwtToken = authHeader.substring(7);
                paylod = jwtTokenProvider.getSubjectFromToken(jwtToken);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(paylod,
                        null, null);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
            } else {
               log.error("Request without jwt token");
            }
        } catch (Exception e) {
            log.error("Invalid authentication token ", e);
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }

    }


    @Override
    public boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !REQUESTMATCHER.matches(request);
    }
}
