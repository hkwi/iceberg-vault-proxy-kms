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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.StandardProtocolFamily;
import java.net.URI;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

class UnixDomainSocketVaultProxyTransport implements VaultProxyTransport {
  private static final String HOST = "localhost";

  private final Path socketPath;

  UnixDomainSocketVaultProxyTransport(URI endpoint) {
    if (endpoint.getPath() == null || endpoint.getPath().isEmpty()) {
      throw new IllegalArgumentException("Vault proxy unix URI must include a socket path");
    }

    this.socketPath = Path.of(endpoint.getPath());
  }

  @Override
  public Response post(String path, Map<String, String> headers, byte[] body) throws IOException {
    try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
      channel.connect(UnixDomainSocketAddress.of(socketPath));

      OutputStream output = Channels.newOutputStream(channel);
      writeRequest(output, path, headers, body);
      output.flush();

      return readResponse(Channels.newInputStream(channel));
    }
  }

  private void writeRequest(
      OutputStream output, String path, Map<String, String> headers, byte[] body)
      throws IOException {
    StringBuilder builder = new StringBuilder();
    builder.append("POST ").append(path).append(" HTTP/1.1\r\n");
    builder.append("Host: ").append(HOST).append("\r\n");
    builder.append("Accept: application/json\r\n");
    builder.append("Content-Type: application/json\r\n");
    builder.append("Content-Length: ").append(body.length).append("\r\n");
    builder.append("Connection: close\r\n");
    headers.forEach((key, value) -> builder.append(key).append(": ").append(value).append("\r\n"));
    builder.append("\r\n");

    output.write(builder.toString().getBytes(StandardCharsets.US_ASCII));
    output.write(body);
  }

  private Response readResponse(InputStream input) throws IOException {
    String headerText =
        new String(
            Http1MessageIO.readHeaderSection(
                input, "Vault proxy returned an incomplete HTTP response"),
            StandardCharsets.US_ASCII);
    List<String> headerLines =
        headerText.isEmpty() ? List.of() : List.of(headerText.split("\r\n"));
    if (headerLines.isEmpty()) {
      throw new IllegalStateException("Vault proxy returned no status line");
    }

    String[] statusParts = headerLines.get(0).split(" ", 3);
    if (statusParts.length < 2) {
      throw new IllegalStateException("Invalid status line: " + headerLines.get(0));
    }

    int statusCode = Integer.parseInt(statusParts[1]);

    Map<String, String> headers = new HashMap<>();
    for (int index = 1; index < headerLines.size(); index++) {
      int separator = headerLines.get(index).indexOf(':');
      if (separator > 0) {
        headers.put(
            headerLines.get(index).substring(0, separator).toLowerCase(Locale.ROOT),
            headerLines.get(index).substring(separator + 1).trim());
      }
    }

    byte[] body;
    if ("chunked".equalsIgnoreCase(headers.get("transfer-encoding"))) {
      body = readChunked(input);
    } else if (headers.containsKey("content-length")) {
      body =
          Http1MessageIO.readFixed(
              input,
              Integer.parseInt(headers.get("content-length")),
              "Vault proxy response ended before reading Content-Length");
    } else {
      body = input.readAllBytes();
    }

    return new Response(statusCode, body);
  }

  private static byte[] readChunked(InputStream input) throws IOException {
    ByteArrayOutputStream decoded = new ByteArrayOutputStream();
    while (true) {
      String sizeLine =
          Http1MessageIO.readAsciiLine(input, "Vault proxy returned an incomplete chunked response");
      int semicolon = sizeLine.indexOf(';');
      String sizeHex = semicolon >= 0 ? sizeLine.substring(0, semicolon) : sizeLine;
      int size = Integer.parseInt(sizeHex.trim(), 16);

      if (size == 0) {
        return decoded.toByteArray();
      }

      decoded.write(
          Http1MessageIO.readFixed(
              input, size, "Vault proxy response ended before reading chunk body"));
      Http1MessageIO.readFixed(
          input, 2, "Vault proxy response ended before reading chunk terminator");
    }
  }
}
