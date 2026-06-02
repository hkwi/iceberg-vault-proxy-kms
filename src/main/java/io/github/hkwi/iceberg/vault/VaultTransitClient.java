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

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
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

  byte[] encrypt(String keyId, byte[] plaintext) {
    return transit(
        "encrypt", keyId, requestWithBinaryField("plaintext", plaintext), "ciphertext", false);
  }

  byte[] decrypt(String keyId, byte[] ciphertext) {
    return transit(
        "decrypt",
        keyId,
        requestWithUtf8StringField("ciphertext", ciphertext),
        "plaintext",
        true);
  }

  private byte[] transit(
      String operation, String keyId, byte[] request, String responseField, boolean decodeBase64) {
    byte[] response = post(operation, keyId, request);
    try {
      return readDataField(response, responseField, decodeBase64);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to parse Vault proxy response", e);
    } finally {
      SensitiveMemory.zero(response);
    }
  }

  private byte[] post(String operation, String keyId, byte[] request) {
    String path = requestPath(operation, keyId);
    VaultProxyTransport.Response response;
    try {
      response = transport.post(path, headers(), request);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to call Vault proxy path " + path, e);
    } finally {
      SensitiveMemory.zero(request);
    }

    if (response.statusCode() != 200) {
      String responseBody = truncate(response.body());
      SensitiveMemory.zero(response.body());
      throw new IllegalStateException(
          String.format(
              "Vault proxy request failed: HTTP %s for %s: %s",
              response.statusCode(), path, responseBody));
    }

    return response.body();
  }

  private static byte[] requestWithBinaryField(String field, byte[] value) {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        JsonGenerator generator = MAPPER.getFactory().createGenerator(output)) {
      generator.writeStartObject();
      generator.writeBinaryField(field, value);
      generator.writeEndObject();
      generator.flush();
      return output.toByteArray();
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to encode Vault proxy request", e);
    }
  }

  private static byte[] requestWithUtf8StringField(String field, byte[] utf8Value) {
    try (ByteArrayOutputStream output = new ByteArrayOutputStream();
        JsonGenerator generator = MAPPER.getFactory().createGenerator(output)) {
      generator.writeStartObject();
      generator.writeFieldName(field);
      generator.writeUTF8String(utf8Value, 0, utf8Value.length);
      generator.writeEndObject();
      generator.flush();
      return output.toByteArray();
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to encode Vault proxy request", e);
    }
  }

  private static byte[] readDataField(byte[] body, String responseField, boolean decodeBase64)
      throws IOException {
    try (JsonParser parser = MAPPER.getFactory().createParser(body)) {
      checkState(parser.nextToken() == JsonToken.START_OBJECT, "Vault proxy response is not JSON");
      while (parser.nextToken() != JsonToken.END_OBJECT) {
        String fieldName = parser.currentName();
        JsonToken valueToken = parser.nextToken();
        if ("data".equals(fieldName)) {
          checkState(valueToken == JsonToken.START_OBJECT, "Vault proxy response data is not JSON");
          return readFieldFromDataObject(parser, responseField, decodeBase64);
        }
        parser.skipChildren();
      }
    }

    throw new IllegalStateException("Vault proxy response has no data object");
  }

  private static byte[] readFieldFromDataObject(
      JsonParser parser, String responseField, boolean decodeBase64) throws IOException {
    while (parser.nextToken() != JsonToken.END_OBJECT) {
      String fieldName = parser.currentName();
      JsonToken valueToken = parser.nextToken();
      if (responseField.equals(fieldName)) {
        checkState(
            valueToken == JsonToken.VALUE_STRING,
            "Vault proxy response has non-string %s",
            responseField);
        if (decodeBase64) {
          return parser.getBinaryValue();
        }
        return parser.getText().getBytes(StandardCharsets.UTF_8);
      }
      parser.skipChildren();
    }

    throw new IllegalStateException(String.format("Vault proxy response has no %s", responseField));
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

  private static String truncate(byte[] value) {
    if (value == null || value.length == 0) {
      return "";
    }
    if (value.length <= 2_048) {
      return new String(value, StandardCharsets.UTF_8);
    }

    return new String(value, 0, 2_048, StandardCharsets.UTF_8) + "...";
  }

  @Override
  public void close() {
    transport.close();
  }
}
