package com.sso.authorizationserver.controller;

import com.sso.authorizationserver.config.RedirectToLoginWhenExpiredException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.IOException;

@ControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(value = RedirectToLoginWhenExpiredException.class)
    public void handleExpiredTokenException(
            HttpServletResponse response,
            HttpServletRequest request)
            throws IOException {

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        SecurityContextHolder.clearContext();
        log.warn("Session has expired, login again to continue");
        response.sendRedirect("/login?expired");
    }
}