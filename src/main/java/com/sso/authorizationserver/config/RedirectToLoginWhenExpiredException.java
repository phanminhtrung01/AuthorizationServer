package com.sso.authorizationserver.config;

public class RedirectToLoginWhenExpiredException extends RuntimeException {
    public RedirectToLoginWhenExpiredException(String s) {
        super(s);
    }
}
