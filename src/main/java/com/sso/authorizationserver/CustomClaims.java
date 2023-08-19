package com.sso.authorizationserver;

import java.util.Map;

public class CustomClaims {
    private static Map<String, Object> instance;


    public static void setInstance(Map<String, Object> mapClaims) {
        instance = mapClaims;
    }

    public static Map<String, Object> getInstance() {
        return instance;
    }
}
