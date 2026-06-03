/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package io.github.hkwi.iceberg.vault;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.rest.ErrorHandlers;
import org.apache.iceberg.rest.HTTPClient;
import org.apache.iceberg.rest.RESTCatalogProperties;
import org.apache.iceberg.rest.RESTClient;
import org.apache.iceberg.rest.RESTUtil;
import org.apache.iceberg.rest.auth.AuthManager;
import org.apache.iceberg.rest.auth.AuthManagers;
import org.apache.iceberg.rest.auth.AuthSession;
import org.apache.iceberg.rest.credentials.Credential;
import org.apache.iceberg.rest.responses.LoadCredentialsResponse;

class VaultProxyAuthTokenProvider implements Closeable {
  private final Map<String, String> properties;
  private final String authHeader;
  private final String authScheme;
  private final String credentialPrefix;
  private final String credentialsEndpoint;
  private final String catalogEndpoint;
  private final String planId;
  private final long refreshPrefetchMs;

  private volatile Token token;
  private volatile HTTPClient rootClient;
  private volatile RESTClient client;
  private AuthManager authManager;
  private AuthSession authSession;

  VaultProxyAuthTokenProvider(Map<String, String> properties) {
    this.properties = Map.copyOf(properties);
    this.authHeader =
        propertyAsString(
            properties,
            VaultProxyProperties.VAULT_PROXY_AUTH_HEADER,
            VaultProxyProperties.VAULT_PROXY_AUTH_HEADER_DEFAULT);
    this.authScheme =
        properties.getOrDefault(
            VaultProxyProperties.VAULT_PROXY_AUTH_SCHEME,
            VaultProxyProperties.VAULT_PROXY_AUTH_SCHEME_DEFAULT);
    this.credentialPrefix =
        propertyAsString(
            properties,
            VaultProxyProperties.VAULT_PROXY_AUTH_CREDENTIAL_PREFIX,
            VaultProxyProperties.VAULT_PROXY_AUTH_CREDENTIAL_PREFIX_DEFAULT);
    this.credentialsEndpoint =
        normalizeCredentialsEndpoint(
            properties.get(VaultProxyProperties.VAULT_PROXY_AUTH_REFRESH_CREDENTIALS_ENDPOINT));
    this.catalogEndpoint = properties.get(CatalogProperties.URI);
    this.planId = properties.get(RESTCatalogProperties.REST_SCAN_PLAN_ID);
    this.refreshPrefetchMs =
        propertyAsLong(
            properties,
            VaultProxyProperties.VAULT_PROXY_AUTH_REFRESH_PREFETCH_MS,
            VaultProxyProperties.VAULT_PROXY_AUTH_REFRESH_PREFETCH_MS_DEFAULT);
    this.token = tokenFromConfig(properties);
  }

  String authHeader() {
    return authHeader;
  }

  String authorizationValue() {
    Token current = currentToken();
    if (current == null) {
      return null;
    }

    if (isNullOrEmpty(authScheme)) {
      return current.value();
    }

    return authScheme + " " + current.value();
  }

  private Token currentToken() {
    Token current = token;
    if (current != null && current.expired(System.currentTimeMillis())) {
      if (isNullOrEmpty(credentialsEndpoint)) {
        throw new IllegalStateException(
            "Vault proxy auth token is expired and no refresh credentials endpoint is configured");
      }
    } else if (!refreshDue(current)) {
      return current;
    }

    if (isNullOrEmpty(credentialsEndpoint)) {
      return current;
    }

    synchronized (this) {
      current = token;
      long now = System.currentTimeMillis();
      if (current != null && !current.expired(now) && !refreshDue(current)) {
        return current;
      }

      token = refreshToken();
      return token;
    }
  }

  private boolean refreshDue(Token current) {
    if (isNullOrEmpty(credentialsEndpoint)) {
      return false;
    }

    if (current == null) {
      return true;
    }

    Long expiresAtMs = current.expiresAtMs();
    return expiresAtMs != null && System.currentTimeMillis() + refreshPrefetchMs >= expiresAtMs;
  }

  private Token refreshToken() {
    LoadCredentialsResponse response = fetchCredentials();
    List<Credential> credentials =
        response.credentials().stream()
            .filter(this::isVaultProxyCredential)
            .collect(Collectors.toList());

    checkState(!credentials.isEmpty(), "Invalid Vault proxy credentials: empty");
    checkState(
        credentials.size() == 1,
        "Invalid Vault proxy credentials: exactly one credential should match");

    Token refreshed = tokenFromConfig(credentials.get(0).config());
    checkState(refreshed != null, "Invalid Vault proxy credentials: auth token not set");
    checkState(
        !refreshed.expired(System.currentTimeMillis()),
        "Invalid Vault proxy credentials: auth token is expired");
    return refreshed;
  }

  private boolean isVaultProxyCredential(Credential credential) {
    boolean prefixMatches =
        isNullOrEmpty(credentialPrefix) || credential.prefix().startsWith(credentialPrefix);
    return prefixMatches
        && credential.config().containsKey(VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN);
  }

  private LoadCredentialsResponse fetchCredentials() {
    return httpClient()
        .get(
            credentialsEndpoint,
            !isNullOrEmpty(planId) ? Map.of("planId", planId) : null,
            LoadCredentialsResponse.class,
            Map.of(),
            ErrorHandlers.defaultErrorHandler());
  }

  private RESTClient httpClient() {
    RESTClient current = client;
    if (current != null) {
      return current;
    }

    synchronized (this) {
      current = client;
      if (current == null) {
        checkState(
            !isNullOrEmpty(catalogEndpoint),
            "Invalid catalog endpoint: %s not set",
            CatalogProperties.URI);

        authManager = AuthManagers.loadAuthManager("vault-proxy-credentials-refresh", properties);
        HTTPClient newRootClient =
            HTTPClient.builder(properties)
                .uri(catalogEndpoint)
                .withHeaders(RESTUtil.configHeaders(properties))
                .build();
        authSession = authManager.catalogSession(newRootClient, properties);
        rootClient = newRootClient;
        current = newRootClient.withAuthSession(authSession);
        client = current;
      }
    }

    return current;
  }

  private static Token tokenFromConfig(Map<String, String> config) {
    String tokenValue = config.get(VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN);
    if (isNullOrEmpty(tokenValue)) {
      return null;
    }

    String expiresAtMs = config.get(VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN_EXPIRES_AT_MS);
    return new Token(tokenValue, isNullOrEmpty(expiresAtMs) ? null : Long.parseLong(expiresAtMs));
  }

  private static String propertyAsString(
      Map<String, String> properties, String property, String defaultValue) {
    String value = properties.get(property);
    return isNullOrEmpty(value) ? defaultValue : value;
  }

  private static String normalizeCredentialsEndpoint(String endpoint) {
    if (isNullOrEmpty(endpoint)) {
      return endpoint;
    }

    String normalized = endpoint;
    while (normalized.startsWith("/")) {
      normalized = normalized.substring(1);
    }

    checkState(
        !normalized.isEmpty(),
        "Invalid Vault proxy refresh credentials endpoint: %s",
        endpoint);
    return normalized;
  }

  private static long propertyAsLong(
      Map<String, String> properties, String property, long defaultValue) {
    String value = properties.get(property);
    return isNullOrEmpty(value) ? defaultValue : Long.parseLong(value);
  }

  private static void checkState(boolean expression, String message, Object... args) {
    if (!expression) {
      throw new IllegalStateException(String.format(message, args));
    }
  }

  private static boolean isNullOrEmpty(String value) {
    return value == null || value.isEmpty();
  }

  @Override
  public void close() {
    closeQuietly(authSession);
    closeQuietly(authManager);
    closeQuietly(rootClient);
  }

  private static void closeQuietly(AutoCloseable closeable) {
    if (closeable == null) {
      return;
    }

    try {
      closeable.close();
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to close Vault proxy auth token provider", e);
    } catch (Exception e) {
      throw new RuntimeException("Failed to close Vault proxy auth token provider", e);
    }
  }

  private record Token(String value, Long expiresAtMs) {
    boolean expired(long nowMs) {
      return expiresAtMs != null && nowMs >= expiresAtMs;
    }
  }
}
