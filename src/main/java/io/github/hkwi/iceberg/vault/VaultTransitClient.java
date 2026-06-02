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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

class VaultTransitClient implements Closeable {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String NAMESPACE_HEADER = "X-Vault-Namespace";

  private final String transitPath;
  private final String namespace;
  private final VaultProxyTransport transport;

  VaultTransitClient(
      URI endpoint,
      String transitPath,
      String namespace,
      int connectTimeoutMs,
      int readTimeoutMs,
      SSLSocketFactory sslSocketFactory) {
    this.transitPath = normalizeTransitPath(transitPath);
    this.namespace = namespace;
    this.transport =
        VaultProxyTransport.create(endpoint, connectTimeoutMs, readTimeoutMs, sslSocketFactory);
  }

  String encrypt(String keyId, String plaintext) {
    return transit("encrypt", "plaintext", "ciphertext", keyId, plaintext);
  }

  String decrypt(String keyId, String ciphertext) {
    return transit("decrypt", "ciphertext", "plaintext", keyId, ciphertext);
  }

  private String transit(
      String operation, String requestField, String responseField, String keyId, String value) {
    ObjectNode request = MAPPER.createObjectNode();
    request.put(requestField, value);

    JsonNode data = post(operation, keyId, request);
    checkState(data.has(responseField), "Vault proxy response has no %s", responseField);
    return data.get(responseField).asText();
  }

  private JsonNode post(String operation, String keyId, ObjectNode request) {
    String path = requestPath(operation, keyId);
    VaultProxyTransport.Response response;
    try {
      response = transport.post(path, headers(), MAPPER.writeValueAsBytes(request));
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to call Vault proxy path " + path, e);
    }

    checkState(
        response.statusCode() == 200,
        "Vault proxy request failed: HTTP %s for %s: %s",
        response.statusCode(),
        path,
        truncate(response.body()));

    try {
      JsonNode data = MAPPER.readTree(response.body()).get("data");
      checkState(data != null, "Vault proxy response has no data object");
      return data;
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to parse Vault proxy response", e);
    }
  }

  private Map<String, String> headers() {
    if (isNullOrEmpty(namespace)) {
      return Map.of();
    }

    return Map.of(NAMESPACE_HEADER, namespace);
  }

  private String requestPath(String operation, String keyId) {
    return "/v1/" + transitPath + "/" + operation + "/" + encodePathSegment(keyId);
  }

  private static String normalizeTransitPath(String transitPath) {
    if (isNullOrEmpty(transitPath)) {
      throw new IllegalArgumentException("Invalid transit path: null");
    }

    String normalized = transitPath;
    while (normalized.startsWith("/")) {
      normalized = normalized.substring(1);
    }

    while (normalized.endsWith("/")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }

    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("Invalid transit path: empty");
    }

    return normalized;
  }

  private static void checkState(boolean expression, String message, Object... args) {
    if (!expression) {
      throw new IllegalStateException(String.format(message, args));
    }
  }

  private static boolean isNullOrEmpty(String value) {
    return value == null || value.isEmpty();
  }

  private static String encodePathSegment(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String truncate(String value) {
    if (value == null || value.length() <= 2_048) {
      return value;
    }

    return value.substring(0, 2_048) + "...";
  }

  @Override
  public void close() {
    transport.close();
  }
}
