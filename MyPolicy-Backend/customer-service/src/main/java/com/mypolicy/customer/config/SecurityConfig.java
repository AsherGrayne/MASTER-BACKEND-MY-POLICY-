package com.mypolicy.customer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.disable())
        .headers(headers -> headers.frameOptions(frame -> frame.disable())) // Allow H2 console
        .authorizeHttpRequests(auth -> auth
            // Allow Registration and Login endpoints publicly
            .requestMatchers(
                new AntPathRequestMatcher("/"),
                new AntPathRequestMatcher("/health"),
                new AntPathRequestMatcher("/api/health"),
                new AntPathRequestMatcher("/error"),
                new AntPathRequestMatcher("/api/v1/customers/register"),
                new AntPathRequestMatcher("/api/v1/customers/login"),
                new AntPathRequestMatcher("/api/v1/actuator/**"),
                new AntPathRequestMatcher("/h2-console/**"))
            .permitAll()
            // All other endpoints require authentication
            .anyRequest().authenticated())
        // Stateless session for microservices
        .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    // Add JWT filter if necessary, but for this service (Customer Master),
    // the primary goal is to *issue* tokens. We might need validation if it calls
    // itself or for specific secured routes.
    // For now, we will handle authentication in the service layer manually for
    // login.

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager();
  }
}
