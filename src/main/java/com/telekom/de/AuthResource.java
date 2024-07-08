package com.telekom.de;

import io.quarkus.elytron.security.common.BcryptUtil;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

@Path("/auth")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    UserRepository userRepository;

    @POST
    @Path("register")
    @Transactional
    public Response register(User user) {

        if(userRepository.findByUsername(user.getUsername()) != null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Usuário já existe").build();
        }

        String passwordEncrypted = BcryptUtil.bcryptHash(user.getPassword());
        user.setPassword(passwordEncrypted);
        user.setRole("User");

        userRepository.persist(user);

        return Response.status(Response.Status.CREATED).entity(user).build();
    }

    @POST
    @Path("login")
    @Transactional
    public Response login(User user) {
        User foundUser = userRepository.findByUsername(user.getUsername());

        if(foundUser == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid username or password").build();
        }

        boolean matches = BcryptUtil.matches(user.getPassword(), foundUser.getPassword());

        if(!matches) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Invalid username or password").build();
        }

        String token = Jwt.issuer("https://example.com/issuer")
                .upn(foundUser.getUsername())
                .groups(new HashSet<>(Collections.singletonList(foundUser.getRole())))
                .sign();

        return Response.ok().entity(token).build();

    }

}
