package com.auth.endpoint;

import java.time.Instant;

public record ClientRegistrationResponse(
        String clientId,
        String clientSecret,
        Instant issuedAt,
        Instant expiresAt
) {}
