package com.github.TheTrueHooha.OAuth.Security.Implementation.Configuration;

import com.github.TheTrueHooha.OAuth.Security.Implementation.Services.OAuthProviderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultOAuthConfiguriation {

    @Autowired
    private OAuthProviderService oAuthProviderService;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
    httpSecurity.authorizeRequests(authorizeRequests -> authorizeRequests
            .anyRequest()
            .authenticated())
            .formLogin(Customizer.withDefaults());
        return httpSecurity.build();
    }

    @Autowired
    public void bindAuthProvider(AuthenticationManagerBuilder authManagerBuilder) {
        authManagerBuilder.authenticationProvider(oAuthProviderService);

    }
}
