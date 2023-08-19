package com.sso.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class OAuth2Config {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository client1registeredClientRepository() {
        TokenSettings tokenSettingsCustom = TokenSettings
                .builder()
                .accessTokenTimeToLive(Duration.ofSeconds(30))
                .refreshTokenTimeToLive(Duration.ofMinutes(1))
                .build();

        RegisteredClient registeredClient1 = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("client1")
                .clientSecret(passwordEncoder().encode("secret1"))
                .scopes(scopes -> {
                    scopes.add("read");
                    scopes.add(OidcScopes.OPENID);
                    scopes.add(OidcScopes.PROFILE);
                    scopes.add(OidcScopes.EMAIL);
                })
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/custom1")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .tokenSettings(tokenSettingsCustom)
                .build();

        RegisteredClient registeredClient2 = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("client2")
                .clientSecret(passwordEncoder().encode("secret2"))
                .scopes(scopes -> {
                    scopes.add("read");
                    scopes.add(OidcScopes.OPENID);
                    scopes.add(OidcScopes.PROFILE);
                    scopes.add(OidcScopes.EMAIL);
                })
                .redirectUri("http://127.0.0.1:8081/login/oauth2/code/custom2")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                })
                .tokenSettings(tokenSettingsCustom)
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient1, registeredClient2);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey)
                .keyID(UUID.randomUUID().toString()).build();
    }

    static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }

        return keyPair;
    }


}
