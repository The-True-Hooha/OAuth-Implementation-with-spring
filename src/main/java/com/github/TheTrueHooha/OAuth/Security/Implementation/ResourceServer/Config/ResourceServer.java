package com.github.TheTrueHooha.OAuth.Security.Implementation.ResourceServer.Config;

import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ResourceServer {

    @SneakyThrows
    @Bean
    SecurityFilterChain securityFilterChain (HttpSecurity httpSecurity) {
        httpSecurity
                .authorizeRequests()
                .mvcMatchers("/api/**")
                .access("hasAuthority('SCOPE_api.read')")
                .and()
                .oauth2ResourceServer()
                .jwt();
        return httpSecurity.build();
    }
}
