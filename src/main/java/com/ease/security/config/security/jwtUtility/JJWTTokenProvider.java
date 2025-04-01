package com.ease.security.config.security.jwtUtility;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JJWTTokenProvider {

    private static SecretKey secretKey = Keys.hmacShaKeyFor("wZgs0GXjuKGaC5ghNgOuCPB4BWAK+SipZz+XgUgz9Gs=".getBytes());
    private static String issuer = "auth0";

    private String generateJwtToken(String subject, int expiryInMinutes) {

        ZonedDateTime zdt = ZonedDateTime.now(ZoneOffset.UTC);;
        return Jwts.builder()
                .subject(subject)
                .issuer(issuer)
                .issuedAt(Date.from(zdt.toInstant()))
                .expiration(Date.from(zdt.plusMinutes(expiryInMinutes).toInstant()))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public String generateJwtToken(String subject) {
        return generateJwtToken(subject, 2);
    }

    public String getSubjectFromToken(String token) {
    try {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();

    } catch (ExpiredJwtException e) {
        log.error("❌ Token has expired");
        throw new RuntimeException("Token expired", e);

    } catch (UnsupportedJwtException e) {
        log.error("❌ Unsupported token format");
        throw new RuntimeException("Unsupported token", e);

    } catch (MalformedJwtException e) {
        log.error("❌ Malformed token (bad format)");
        throw new RuntimeException("Malformed token", e);

    } catch (SecurityException e) {
        log.error("❌ Signature validation failed");
        throw new RuntimeException("Invalid signature", e);

    } catch (IllegalArgumentException e) {
        log.error("❌ Token is null or empty");
        throw new RuntimeException("Invalid token input", e);

    } catch (JwtException e) {
        log.error("❌ General JWT exception");
        throw new RuntimeException("JWT error", e);
    }
}

}
