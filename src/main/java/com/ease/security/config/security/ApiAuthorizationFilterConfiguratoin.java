package com.ease.security.config.security;

import java.io.IOException;
import java.util.Arrays;

import com.ease.security.config.security.jwtUtility.JwtTokenPayload;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
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
            new AntPathRequestMatcher("/v3/api-docs/**"), new AntPathRequestMatcher("/swagger-resources/**"),
            new AntPathRequestMatcher("/api/v1/user/onboard-users*"))));

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
        JwtTokenPayload paylod = null;
        String username = null;
        try {
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                jwtToken = authHeader.substring(7);
                ObjectMapper om = new ObjectMapper();
                om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false) .findAndRegisterModules();
                String details = jwtTokenProvider.getSubjectFromToken(jwtToken);
                log.info("token payload details: {}", details);
                paylod = om.readValue(details, JwtTokenPayload.class);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(paylod.getEmail(),
                        null, null);
                authentication.setDetails(paylod);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                log.error("Request without jwt token");
            }
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported token format");
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (MalformedJwtException e) {
            log.error("Malformed token (bad format)");
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (SecurityException e) {
            log.error("Signature validation failed");
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (IllegalArgumentException e) {
            log.error("Token is null or empty");
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        } catch (JwtException e) {
            log.error("General JWT exception");
            SecurityContextHolder.clearContext();
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }catch (Exception e) {
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
