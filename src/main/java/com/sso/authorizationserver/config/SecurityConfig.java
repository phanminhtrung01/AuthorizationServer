package com.sso.authorizationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Slf4j
public class SecurityConfig {

    @Bean
    @Order(1)
    protected SecurityFilterChain configureOAuth(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults());

        return http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(oauth2RSConfig ->
                        oauth2RSConfig.jwt(withDefaults()))
                .oauth2Client(withDefaults())
                .build();
    }

    @Bean
    @Order(2)
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorizeRequest -> authorizeRequest
                        .requestMatchers("/login", "/css/**"
                                , "/js/**", "/images/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2Config -> oauth2Config
                        .loginPage("/login")
                        .successHandler(new CustomAuthenticationSuccessHandler())
                        .defaultSuccessUrl("/")
                )
                .logout(logoutConfig -> logoutConfig.logoutSuccessUrl("/"))
                .build();

    }

    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(
            ApplicationEventPublisher applicationEventPublisher) {
        return new DefaultAuthenticationEventPublisher(applicationEventPublisher);
    }
}
