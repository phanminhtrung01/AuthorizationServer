package com.sso.authorizationserver.config;

import com.sso.authorizationserver.CustomClaims;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class JwtTokenCustomizerConfig {

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {

        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                customClaims(context);
            }

            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                customClaims(context);
            }

        };
    }

    private void customClaims(JwtEncodingContext context) {
        Map<String, Object> mapClaims = CustomClaims.getInstance();
        Map<String, Object> mapClaimsAccessToken = new HashMap<>();
        if (mapClaims != null) {
            mapClaimsAccessToken.put("sub", mapClaims.get("sub"));
            mapClaimsAccessToken.put("id", mapClaims.get("id"));
            context.getClaims().claims((claims) -> claims
                    .putAll(mapClaimsAccessToken));
        } else {
            throw new RedirectToLoginWhenExpiredException("Login again!");
        }
    }
}