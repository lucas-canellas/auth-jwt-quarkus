package com.telekom.de;

import io.smallrye.jwt.build.Jwt;
import org.eclipse.microprofile.jwt.Claims;

import java.util.Arrays;
import java.util.HashSet;

/**
 * Utility to generate the JWT token string.
 */
public class JWTTokenGeneration {
    /**
     * JWT token Generation
     */
    public static void main(String[] args) {
        String token = Jwt.issuer("https://example.com/issuer")
                .upn("ishaq@quarkus.io")
                .groups(new HashSet<>(Arrays.asList("User", "Admin")))
                .claim(Claims.birthdate.name(), "2024-04-31")
                .sign();
        System.out.println(token);

    }
}