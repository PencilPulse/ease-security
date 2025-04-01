package com.ease.security.config.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JwtCustomScurityConfigurer {

    private final UserDetailsService userDetailsService;
    private final JJWTTokenProvider jjwtTokenProvider;
    private AuthenticationManager authenticationManager;

    /**
     * This method configures the custom filter for JWT authentication in the security filter chain.
     * It adds a custom login filter before the UsernamePasswordAuthenticationFilter.
     *
     * @param httpSecurity The HttpSecurity object used to configure security settings.
     */
    public void customFilterConfigure(HttpSecurity httpSecurity) {
        httpSecurity.addFilterBefore(new LoginFilterConfig(jjwtTokenProvider, authenticationManager), UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(new ApiAuthorizationFilterConfiguratoin(jjwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
                    // .addFilterBefore(null, UsernamePasswordAuthenticationFilter.class);
    }

}
