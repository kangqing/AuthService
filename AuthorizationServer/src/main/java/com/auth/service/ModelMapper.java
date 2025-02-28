package com.auth.service;


import com.auth.entity.OAuth2RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

final class ModelMapper {

    static OAuth2RegisteredClient convertOAuth2RegisteredClient(RegisteredClient registeredClient) {
        OAuth2RegisteredClient.ClientSettings clientSettings = new OAuth2RegisteredClient.ClientSettings(
                registeredClient.getClientSettings().isRequireProofKey(),
                registeredClient.getClientSettings().isRequireAuthorizationConsent(),
                registeredClient.getClientSettings().getJwkSetUrl(),
                registeredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm(),
                registeredClient.getClientSettings().getX509CertificateSubjectDN());

        OAuth2RegisteredClient.TokenSettings tokenSettings = new OAuth2RegisteredClient.TokenSettings(
                registeredClient.getTokenSettings().getAuthorizationCodeTimeToLive(),
                registeredClient.getTokenSettings().getAccessTokenTimeToLive(),
                registeredClient.getTokenSettings().getAccessTokenFormat(),
                registeredClient.getTokenSettings().getDeviceCodeTimeToLive(),
                registeredClient.getTokenSettings().isReuseRefreshTokens(),
                registeredClient.getTokenSettings().getRefreshTokenTimeToLive(),
                registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm(),
                registeredClient.getTokenSettings().isX509CertificateBoundAccessTokens());

        return new OAuth2RegisteredClient(registeredClient.getId(), registeredClient.getClientId(),
                registeredClient.getClientIdIssuedAt(), registeredClient.getClientSecret(),
                registeredClient.getClientSecretExpiresAt(), registeredClient.getClientName(),
                registeredClient.getClientAuthenticationMethods(), registeredClient.getAuthorizationGrantTypes(),
                registeredClient.getRedirectUris(), registeredClient.getPostLogoutRedirectUris(),
                registeredClient.getScopes(), clientSettings, tokenSettings);
    }

    static RegisteredClient convertRegisteredClient(OAuth2RegisteredClient oauth2RegisteredClient) {
        ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder()
                .requireProofKey(oauth2RegisteredClient.getClientSettings().isRequireProofKey())
                .requireAuthorizationConsent(oauth2RegisteredClient.getClientSettings().isRequireAuthorizationConsent());
        if (StringUtils.hasText(oauth2RegisteredClient.getClientSettings().getJwkSetUrl())) {
            clientSettingsBuilder.jwkSetUrl(oauth2RegisteredClient.getClientSettings().getJwkSetUrl());
        }
        if (oauth2RegisteredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm() != null) {
            clientSettingsBuilder.tokenEndpointAuthenticationSigningAlgorithm(
                    oauth2RegisteredClient.getClientSettings().getTokenEndpointAuthenticationSigningAlgorithm());
        }
        if (StringUtils.hasText(oauth2RegisteredClient.getClientSettings().getX509CertificateSubjectDN())) {
            clientSettingsBuilder
                    .x509CertificateSubjectDN(oauth2RegisteredClient.getClientSettings().getX509CertificateSubjectDN());
        }
        ClientSettings clientSettings = clientSettingsBuilder.build();

        TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
        if (oauth2RegisteredClient.getTokenSettings().getAuthorizationCodeTimeToLive() != null) {
            tokenSettingsBuilder.authorizationCodeTimeToLive(
                    oauth2RegisteredClient.getTokenSettings().getAuthorizationCodeTimeToLive());
        }
        if (oauth2RegisteredClient.getTokenSettings().getAccessTokenTimeToLive() != null) {
            tokenSettingsBuilder
                    .accessTokenTimeToLive(oauth2RegisteredClient.getTokenSettings().getAccessTokenTimeToLive());
        }
        if (oauth2RegisteredClient.getTokenSettings().getAccessTokenFormat() != null) {
            tokenSettingsBuilder.accessTokenFormat(oauth2RegisteredClient.getTokenSettings().getAccessTokenFormat());
        }
        if (oauth2RegisteredClient.getTokenSettings().getDeviceCodeTimeToLive() != null) {
            tokenSettingsBuilder
                    .deviceCodeTimeToLive(oauth2RegisteredClient.getTokenSettings().getDeviceCodeTimeToLive());
        }
        tokenSettingsBuilder.reuseRefreshTokens(oauth2RegisteredClient.getTokenSettings().isReuseRefreshTokens());
        if (oauth2RegisteredClient.getTokenSettings().getRefreshTokenTimeToLive() != null) {
            tokenSettingsBuilder
                    .refreshTokenTimeToLive(oauth2RegisteredClient.getTokenSettings().getRefreshTokenTimeToLive());
        }
        if (oauth2RegisteredClient.getTokenSettings().getIdTokenSignatureAlgorithm() != null) {
            tokenSettingsBuilder
                    .idTokenSignatureAlgorithm(oauth2RegisteredClient.getTokenSettings().getIdTokenSignatureAlgorithm());
        }
        tokenSettingsBuilder.x509CertificateBoundAccessTokens(
                oauth2RegisteredClient.getTokenSettings().isX509CertificateBoundAccessTokens());
        TokenSettings tokenSettings = tokenSettingsBuilder.build();

        RegisteredClient.Builder registeredClientBuilder = RegisteredClient.withId(oauth2RegisteredClient.getId())
                .clientId(oauth2RegisteredClient.getClientId())
                .clientIdIssuedAt(oauth2RegisteredClient.getClientIdIssuedAt())
                .clientSecret(oauth2RegisteredClient.getClientSecret())
                .clientSecretExpiresAt(oauth2RegisteredClient.getClientSecretExpiresAt())
                .clientName(oauth2RegisteredClient.getClientName())
                .clientAuthenticationMethods((clientAuthenticationMethods) -> clientAuthenticationMethods
                        .addAll(oauth2RegisteredClient.getClientAuthenticationMethods()))
                .authorizationGrantTypes((authorizationGrantTypes) -> authorizationGrantTypes
                        .addAll(oauth2RegisteredClient.getAuthorizationGrantTypes()))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings);
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getRedirectUris())) {
            registeredClientBuilder.redirectUris((redirectUris) -> redirectUris.addAll(oauth2RegisteredClient.getRedirectUris()));
        }
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getPostLogoutRedirectUris())) {
            registeredClientBuilder.postLogoutRedirectUris((postLogoutRedirectUris) ->
                    postLogoutRedirectUris.addAll(oauth2RegisteredClient.getPostLogoutRedirectUris()));
        }
        if (!CollectionUtils.isEmpty(oauth2RegisteredClient.getScopes())) {
            registeredClientBuilder.scopes((scopes) -> scopes.addAll(oauth2RegisteredClient.getScopes()));
        }

        return registeredClientBuilder.build();
    }

}
