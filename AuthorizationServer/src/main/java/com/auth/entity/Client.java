package com.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.Instant;

@Data
@Entity
@Table(name = "t_client")
public class Client {
    @Id
    @Column(name = "id")
    private String id;

    @Column(name = "clientId")
    private String clientId;

    @Column(name = "clientIdIssuedAt")
    private Instant clientIdIssuedAt;

    @Column(name = "clientSecret")
    private String clientSecret;

    @Column(name = "clientSecretExpiresAt")
    private Instant clientSecretExpiresAt;

    @Column(name = "clientName")
    private String clientName;

    @Column(name = "clientAuthenticationMethods", length = 1000)
    private String clientAuthenticationMethods;

    @Column(name = "authorizationGrantTypes", length = 1000)
    private String authorizationGrantTypes;

    @Column(name = "redirectUris", length = 1000)
    private String redirectUris;

    @Column(name = "postLogoutRedirectUris", length = 1000)
    private String postLogoutRedirectUris;

    @Column(name = "scopes", length = 1000)
    private String scopes;

    @Column(name = "clientSettings", length = 2000)
    private String clientSettings;

    @Column(name = "tokenSettings", length = 2000)
    private String tokenSettings;
}