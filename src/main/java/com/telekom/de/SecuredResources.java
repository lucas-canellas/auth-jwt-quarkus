package com.telekom.de;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/secured")
public class SecuredResources {

    @Inject
    JsonWebToken jwtWebToken;
    @Inject
    @Claim(standard = Claims.birthdate)
    ClaimValue<String> birthdate;

    @GET
    @Path("allow-all")
    @PermitAll
    @Produces(MediaType.TEXT_PLAIN)
    public String allowAll(@Context SecurityContext ctx) {
        return getResponse(ctx);
    }

    @GET
    @Path("allowed-roles")
    @RolesAllowed({ "User", "Admin" })
    @Produces(MediaType.TEXT_PLAIN)
    public String allowedRoles(@Context SecurityContext ctx) {
        return getResponse(ctx) + ", birthdate: " + jwtWebToken.getClaim("birthdate").toString();
    }

    @GET
    @Path("admin-roles-allowed")
    @RolesAllowed("Admin")
    @Produces(MediaType.TEXT_PLAIN)
    public String adminRolesAllowed(@Context SecurityContext ctx) {
        return getResponse(ctx) + ", birthdate: " + birthdate;
    }

    private String getResponse(SecurityContext ctx) {
        String name;
        if (ctx.getUserPrincipal() == null) {
            name = "anonymous";
        } else if (!ctx.getUserPrincipal().getName().equals(jwtWebToken.getName())) {
            throw new jakarta.ws.rs.InternalServerErrorException("The arrangement of Principal and JsonWebToken names is incorrect");
        } else {
            name = ctx.getUserPrincipal().getName();
        }
        return String.format("Hi %s,"
                        + " isHttps: %s,"
                        + " authScheme: %s,"
                        + " hasJWT: %s",
                name, ctx.isSecure(), ctx.getAuthenticationScheme(), hasJwt());
    }

    private boolean hasJwt() {
        return jwtWebToken.getClaimNames() != null;
    }
}