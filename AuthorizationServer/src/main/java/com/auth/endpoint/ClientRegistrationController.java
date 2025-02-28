package com.auth.endpoint;

import com.auth.service.ClientRegistrar;
import jakarta.annotation.Resource;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/oauth2/register")
public class ClientRegistrationController {

    @Resource
    private ClientRegistrar clientRegistrar;

    @PostMapping
    //@PreAuthorize("hasAuthority('client.create')")
    public ResponseEntity<ClientRegistrationResponse> register(
            @Valid @RequestBody ClientRegistrationRequest request) {

        RegisteredClient client = clientRegistrar.registerClient(request);

        return ResponseEntity.ok(
                new ClientRegistrationResponse(
                        client.getClientId(),
                        client.getClientSecret(),
                        client.getClientIdIssuedAt(),
                        client.getClientSecretExpiresAt()
                )
        );
    }
}

