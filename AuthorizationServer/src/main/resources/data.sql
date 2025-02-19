INSERT INTO T_CLIENT (ID, CLIENT_ID, CLIENT_ID_ISSUED_AT, CLIENT_SECRET, CLIENT_SECRET_EXPIRES_AT, CLIENT_NAME, CLIENT_AUTHENTICATION_METHODS, AUTHORIZATION_GRANT_TYPES, REDIRECT_URIS, POST_LOGOUT_REDIRECT_URIS, SCOPES, CLIENT_SETTINGS, TOKEN_SETTINGS)
VALUES ('1', 'oidc-client', CURRENT_TIMESTAMP, '{noop}123456', NULL, 'OIDC Client', 'client_secret_basic', 'client_credentials', NULL, NULL, 'read', '{
  "clientName": "MyApp",
  "clientUri": "https://myapp.com",
  "logoUri": "https://myapp.com/logo.png",
  "contacts": ["support@myapp.com"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "responseTypes": ["code"],
  "postLogoutRedirectUris": ["https://myapp.com/logout"],
  "accessTokenValidity": 3600,
  "refreshTokenValidity": 1209600
}', '{
  "accessTokenValidity": 3600,
  "refreshTokenValidity": 1209600,
  "idTokenValidity": 3600,
  "tokenEndpointAuthMethod": "client_secret_basic",
  "reuseRefreshTokens": true,
  "refreshTokenMaxAge": 2592000,
  "authorizationCodeValidity": 600,
  "accessTokenFormat": "JWT"
}');