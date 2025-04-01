package com.ease.security.config.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;
import com.ease.security.utility.PasswordBycryptEncrypt;

/**
 * SecurityConfiguration class is responsible for configuring the security settings of the application.
 * It uses Spring Security to define the security filter chain, authentication provider,
 */
@Configuration
@EnableWebSecurity(debug = true)
public class SecurityConfiguration {

        @Autowired
        UserDetailsService userDetailsService;
        @Autowired
        PasswordBycryptEncrypt passwordBycryptEncrypt;
        @Autowired
        JJWTTokenProvider jjwtTokenProvider;

        /**
         * This method configures the security filter chain for the application.
         * It sets up session management, authorization rules, and other security
         * configurations.
         *
         * @param httpSecurity The HttpSecurity object used to configure security
         *                     settings.
         * @return The configured SecurityFilterChain object.
         * @throws Exception If an error occurs during configuration.
         */

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

                httpSecurity
                                .sessionManagement(sessionManagement -> sessionManagement
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/api/v1/user/onboard-users*").permitAll()
                                                .requestMatchers("/swagger-ui*/**","/v3/api-docs/**").permitAll()
                                                .requestMatchers(HttpMethod.POST, "/error").permitAll()
                                                .requestMatchers("/actuator/**").permitAll()
                                                .anyRequest().authenticated())
                                .cors(cors -> cors.disable())
                                .csrf(crsf -> crsf.disable())
                                //.addFilterBefore(new LoginFilterConfig(jjwtTokenProvider, authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                                .headers(header -> header.frameOptions(frameOption -> frameOption.disable())
                                                .contentSecurityPolicy(csp -> csp.policyDirectives("script-src 'self'"))
                                                .xssProtection(xss -> xss.disable()))
                                .logout(logout -> logout.disable())
                                .formLogin(formLogin -> formLogin.disable());
                new JwtCustomScurityConfigurer(userDetailsService, jjwtTokenProvider, authenticationManager())
                                .customFilterConfigure(httpSecurity);
                return httpSecurity.build();
        }

        /**
         * This method configures the DaoAuthenticationProvider for user authentication.
         * It sets the UserDetailsService and PasswordEncoder for the provider.
         *
         * @return The configured DaoAuthenticationProvider object.
         */
        public DaoAuthenticationProvider daoAuthenticationProvider() {
                DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
                daoAuthenticationProvider.setUserDetailsService(userDetailsService);
                daoAuthenticationProvider.setPasswordEncoder(passwordBycryptEncrypt);
                return daoAuthenticationProvider;
        }

        /**
         * This method configures the AuthenticationManager for the application.
         * It uses the DaoAuthenticationProvider for authentication.
         *
         * @return The configured AuthenticationManager object.
         * @throws Exception If an error occurs during configuration.
         */
        @Bean
        public AuthenticationManager authenticationManager() throws Exception {
                return new ProviderManager(List.of(daoAuthenticationProvider()));
        }
}
