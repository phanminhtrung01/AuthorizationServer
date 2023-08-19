package com.sso.authorizationserver.config;

import com.sso.authorizationserver.CustomClaims;
import com.sso.authorizationserver.ProviderAuth;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class AuthenticationEvents {

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        Authentication authentication = success.getAuthentication();
        if (authentication instanceof
                OAuth2LoginAuthenticationToken auth2LoginAuthenticationToken) {
            String providerName = auth2LoginAuthenticationToken
                    .getClientRegistration()
                    .getRegistrationId().toUpperCase();

            if (Arrays.stream(ProviderAuth.values())
                    .map(Enum::name)
                    .toList()
                    .contains(providerName)) {
                Map<String, Object> mapClaims = new HashMap<>();
                mapClaims.put("at_provider", auth2LoginAuthenticationToken
                        .getAccessToken()
                        .getTokenValue());
                String refreshToken;
                if (auth2LoginAuthenticationToken
                        .getRefreshToken() == null)
                    refreshToken = "";
                else
                    refreshToken = auth2LoginAuthenticationToken
                            .getRefreshToken()
                            .getTokenValue();
                mapClaims.put("rt_provider", refreshToken);
                mapClaims.put("id", authentication.getName());

                OAuth2User oAuth2User = auth2LoginAuthenticationToken.getPrincipal();
                List<String> roles = new ArrayList<>();
                if (providerName.equals(ProviderAuth.OKTA.name())) {
                    // ...
                    mapClaims.put("sub", oAuth2User.getAttributes().get("name"));

                    List<String> groups = oAuth2User.getAttribute("groups");
                    if (groups != null) {
                        roles.addAll(groups);
                    }
                } else if (providerName.equals(ProviderAuth.GITHUB.name())) {
                    // ...
                    mapClaims.put("sub", auth2LoginAuthenticationToken
                            .getPrincipal()
                            .getAttributes()
                            .get("login"));

                    Boolean checkRole = oAuth2User.getAttribute("site_admin");
                    if (checkRole != null) {
                        if (checkRole)
                            roles.add("ADMIN");
                        else
                            roles.add("USER");
                    }
                } else {
                    // ...
                    mapClaims.put("sub", auth2LoginAuthenticationToken
                            .getPrincipal()
                            .getAttributes()
                            .get("name"));
                }

                mapClaims.put("authorities", roles);
                mapClaims.put("provider", providerName);

                CustomClaims.setInstance(mapClaims);
            }
        }
    }

}
