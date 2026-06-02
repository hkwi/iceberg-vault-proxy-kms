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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

class UrlConnectionVaultProxyTransport implements VaultProxyTransport {
  private final URI endpoint;
  private final int connectTimeoutMs;
  private final int readTimeoutMs;
  private final SSLSocketFactory sslSocketFactory;

  UrlConnectionVaultProxyTransport(
      URI endpoint, int connectTimeoutMs, int readTimeoutMs, SSLSocketFactory sslSocketFactory) {
    String rawPath = endpoint.getRawPath();
    if (rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath)) {
      throw new IllegalArgumentException(
          "Vault proxy HTTP(S) URI must not contain a path: " + endpoint);
    }

    this.endpoint = endpoint;
    this.connectTimeoutMs = connectTimeoutMs;
    this.readTimeoutMs = readTimeoutMs;
    this.sslSocketFactory = sslSocketFactory;
  }

  @Override
  public Response post(String path, Map<String, String> headers, byte[] body) throws IOException {
    URL url = endpoint.resolve(path).toURL();
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    if (sslSocketFactory != null && connection instanceof HttpsURLConnection httpsConnection) {
      httpsConnection.setSSLSocketFactory(sslSocketFactory);
    }

    connection.setRequestMethod("POST");
    connection.setConnectTimeout(connectTimeoutMs);
    connection.setReadTimeout(readTimeoutMs);
    connection.setDoOutput(true);
    connection.setRequestProperty("Accept", "application/json");
    connection.setRequestProperty("Content-Type", "application/json");
    headers.forEach(connection::setRequestProperty);
    connection.setFixedLengthStreamingMode(body.length);

    try (OutputStream output = connection.getOutputStream()) {
      output.write(body);
    }

    int statusCode = connection.getResponseCode();
    try (InputStream input =
        statusCode >= 400 ? connection.getErrorStream() : connection.getInputStream()) {
      return new Response(
          statusCode, input == null ? new byte[0] : VaultProxyTransport.readBody(input));
    } finally {
      connection.disconnect();
    }
  }
}
