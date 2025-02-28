package com.auth.endpoint;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.hibernate.validator.constraints.URL;

import java.util.List;

// DTO 定义
public record ClientRegistrationRequest(
        @NotBlank String clientName,
        @NotEmpty List<String> grantTypes,
        @NotEmpty List<@URL String> redirectUris,
        String scope
) {}
