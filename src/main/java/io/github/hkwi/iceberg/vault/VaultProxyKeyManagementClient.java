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

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;
import org.apache.iceberg.encryption.KeyManagementClient;

/**
 * KMS client that talks to a local Vault Proxy and lets the proxy own Vault authentication.
 *
 * <p>The proxy is expected to expose Vault Transit compatible endpoints on localhost HTTP(S), or
 * over a Unix domain socket.
 */
public class VaultProxyKeyManagementClient implements KeyManagementClient {
  private Map<String, String> properties;

  private transient volatile VaultTransitClient transitClient;

  @Override
  public void initialize(Map<String, String> newProperties) {
    this.properties = new HashMap<>(newProperties);
    this.transitClient = newTransitClient();
  }

  @Override
  public ByteBuffer wrapKey(ByteBuffer key, String wrappingKeyId) {
    byte[] keyBytes = new byte[key.remaining()];
    key.duplicate().get(keyBytes);

    try {
      String plaintext = Base64.getEncoder().encodeToString(keyBytes);
      String ciphertext = transitClient().encrypt(wrappingKeyId, plaintext);
      return ByteBuffer.wrap(ciphertext.getBytes(StandardCharsets.UTF_8));
    } finally {
      SensitiveMemory.zero(keyBytes);
    }
  }

  @Override
  public ByteBuffer unwrapKey(ByteBuffer wrappedKey, String wrappingKeyId) {
    byte[] ciphertextBytes = new byte[wrappedKey.remaining()];
    wrappedKey.duplicate().get(ciphertextBytes);

    byte[] plaintextBytes = null;
    try {
      String ciphertext = new String(ciphertextBytes, StandardCharsets.UTF_8);
      String plaintext = transitClient().decrypt(wrappingKeyId, ciphertext);
      plaintextBytes = Base64.getDecoder().decode(plaintext);
      return SensitiveMemory.directBufferFrom(plaintextBytes);
    } finally {
      SensitiveMemory.zero(ciphertextBytes);
      SensitiveMemory.zero(plaintextBytes);
    }
  }

  private VaultTransitClient transitClient() {
    if (properties == null) {
      throw new IllegalStateException("Vault proxy KMS client is not initialized");
    }

    if (transitClient == null) {
      synchronized (this) {
        if (transitClient == null) {
          transitClient = newTransitClient();
        }
      }
    }

    return transitClient;
  }

  private VaultTransitClient newTransitClient() {
    URI uri =
        URI.create(
            properties.getOrDefault(
                VaultProxyProperties.VAULT_PROXY_URI,
                VaultProxyProperties.VAULT_PROXY_URI_DEFAULT));

    String transitPath =
        properties.getOrDefault(
            VaultProxyProperties.VAULT_PROXY_TRANSIT_PATH,
            VaultProxyProperties.VAULT_PROXY_TRANSIT_PATH_DEFAULT);

    int connectTimeoutMs =
        propertyAsInt(
            properties,
            VaultProxyProperties.VAULT_PROXY_CONNECT_TIMEOUT_MS,
            VaultProxyProperties.VAULT_PROXY_CONNECT_TIMEOUT_MS_DEFAULT);

    int readTimeoutMs =
        propertyAsInt(
            properties,
            VaultProxyProperties.VAULT_PROXY_READ_TIMEOUT_MS,
            VaultProxyProperties.VAULT_PROXY_READ_TIMEOUT_MS_DEFAULT);

    SSLSocketFactory sslSocketFactory = sslSocketFactory(uri);

    return new VaultTransitClient(
        uri,
        transitPath,
        properties.get(VaultProxyProperties.VAULT_PROXY_NAMESPACE),
        connectTimeoutMs,
        readTimeoutMs,
        sslSocketFactory);
  }

  private SSLSocketFactory sslSocketFactory(URI uri) {
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      return null;
    }

    return VaultProxySslContext.sslSocketFactory(properties);
  }

  private static int propertyAsInt(
      Map<String, String> properties, String property, int defaultValue) {
    String value = properties.get(property);
    return value != null ? Integer.parseInt(value) : defaultValue;
  }

  @Override
  public void close() {
    if (transitClient != null) {
      transitClient.close();
    }
  }
}
