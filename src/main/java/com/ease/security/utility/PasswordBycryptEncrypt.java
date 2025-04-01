package com.ease.security.utility;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class PasswordBycryptEncrypt extends BCryptPasswordEncoder {

    public String encryptPassword(String password) {
        return this.encode(password);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        boolean isMatch = false;
        if (rawPassword == null || encodedPassword == null) {
            log.info("Raw password or encoded password is null.");
            return false;
        }
        try {
            isMatch = super.matches(rawPassword, encodedPassword);
        } catch (IllegalArgumentException e) {
            log.error("Invalid password format: {}", e);
            return false;
        } catch (NullPointerException e) {
            log.error("Null password provided: {}" , e);
            return false;
        } catch (Exception e) {
            log.error("Null password provided: {}", e);
            return false;
        }
        return isMatch;
    }
}

