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
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;

interface VaultProxyTransport extends Closeable {
  Response post(String path, Map<String, String> headers, byte[] body) throws IOException;

  static VaultProxyTransport create(
      URI endpoint, int connectTimeoutMs, int readTimeoutMs, SSLSocketFactory sslSocketFactory) {
    String scheme = endpoint.getScheme();
    if (scheme == null || scheme.isEmpty()) {
      throw new IllegalArgumentException("Vault proxy URI has no scheme");
    }

    return switch (scheme.toLowerCase(Locale.ROOT)) {
      case "http", "https" ->
          new UrlConnectionVaultProxyTransport(
              endpoint, connectTimeoutMs, readTimeoutMs, sslSocketFactory);
      case "unix" -> new UnixDomainSocketVaultProxyTransport(endpoint);
      default ->
          throw new IllegalArgumentException("Unsupported Vault proxy URI scheme: " + scheme);
    };
  }

  @Override
  default void close() {}

  record Response(int statusCode, String body) {}

  static String readUtf8(InputStream input) throws IOException {
    return new String(input.readAllBytes(), StandardCharsets.UTF_8);
  }
}
