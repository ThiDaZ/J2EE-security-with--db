package com.chopsticks.app.security.security;

import com.chopsticks.app.security.util.JWTUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.security.enterprise.AuthenticationException;
import jakarta.security.enterprise.AuthenticationStatus;
import jakarta.security.enterprise.authentication.mechanism.http.AuthenticationParameters;
import jakarta.security.enterprise.authentication.mechanism.http.AutoApplySession;
import jakarta.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import jakarta.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import jakarta.security.enterprise.identitystore.CredentialValidationResult;
import jakarta.security.enterprise.identitystore.IdentityStore;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.core.HttpHeaders;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@AutoApplySession
@ApplicationScoped
public class AuthMechanism implements HttpAuthenticationMechanism {

    @Inject
    private IdentityStore identityStore;

    private static final Set<String> WHITELIST = Set.of(
            "/login",
            "/register",
            "/auth/login",
            "/auth/register",
            "/public"
    );

    private boolean isWhitelisted(String path) {
        return WHITELIST.stream().anyMatch(path::startsWith);
    }

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest req, HttpServletResponse resp, HttpMessageContext ctx) throws AuthenticationException {

//        String path = req.getServletPath();
//        System.out.println("path: " + path);
//        if (isWhitelisted(path)) {
//            return ctx.doNothing();
//        }

        String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {

            try {
                String token = authHeader.substring(7);
                Claims claims = JWTUtil.parseToken(token).getPayload();
                String username = claims.getSubject();
                List roles = claims.get("roles", List.class);

                CredentialValidationResult result = new CredentialValidationResult(username, new HashSet(roles));
                return ctx.notifyContainerAboutLogin(result);
            } catch (JwtException e) {
                return ctx.responseUnauthorized();
            }

        }


        AuthenticationParameters parameters = ctx.getAuthParameters();
        if (parameters.getCredential() != null) {
            CredentialValidationResult result = identityStore.validate(parameters.getCredential());
            if (result.getStatus() == CredentialValidationResult.Status.VALID) {
                return ctx.notifyContainerAboutLogin(result);
            } else {
                return AuthenticationStatus.SEND_FAILURE;
            }
        }

        if (ctx.isProtected()) {
            try {
                resp.sendRedirect(req.getContextPath() + "/login.jsp");
                return AuthenticationStatus.SEND_CONTINUE;
            } catch (IOException e) {
                throw new RuntimeException("Redirect failed", e);
            }
        }


        return ctx.doNothing();
    }
}
