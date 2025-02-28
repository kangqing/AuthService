package com.auth.service;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.auth.endpoint.ClientRegistrationRequest;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@Service
public class ClientRegistrar {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    // 改用 Repository 注入
    public ClientRegistrar(RegisteredClientRepository registeredClientRepository,
                           PasswordEncoder passwordEncoder) {
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = passwordEncoder;
    }




    public RegisteredClient registerClient(ClientRegistrationRequest request) {
        // 参数校验
        //validateRequest(request);

        // 构建 RegisteredClient
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(UUID.randomUUID().toString())
                .clientSecret(passwordEncoder.encode(generateSecureSecret())) // 加密存储
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantTypes(grantTypes ->
                        grantTypes.addAll(convertGrantTypes(request.grantTypes())))
                .redirectUris(uris -> uris.addAll(request.redirectUris()))
                .scopes(scopes -> scopes.addAll(List.of(request.scope().split(" "))))
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .build())
                .build();

        // 保存到 Redis
        registeredClientRepository.save(registeredClient);
        return registeredClient;
    }

    private String generateSecureSecret() {
        return "123456";
    }

    // 辅助方法（需实现参数校验和类型转换）
    private Set<AuthorizationGrantType> convertGrantTypes(List<String> grantTypes) {
        return grantTypes.stream()
                .map(AuthorizationGrantType::new)
                .collect(Collectors.toSet());
    }



}


