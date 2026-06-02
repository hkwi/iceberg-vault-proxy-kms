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
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

class LocalVaultProxy implements Closeable {
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String CIPHERTEXT_PREFIX = "vault:v1:";

  private final String uri;
  private final Closeable server;
  private final ExecutorService executor;
  private final List<Request> requests;
  private final Path socketPath;

  private volatile boolean closed;

  static LocalVaultProxy tcp() throws IOException {
    ServerSocket serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    LocalVaultProxy proxy =
        new LocalVaultProxy("http://127.0.0.1:" + serverSocket.getLocalPort(), serverSocket, null);
    proxy.executor.submit(() -> proxy.serveTcp(serverSocket));
    return proxy;
  }

  static LocalVaultProxy unix(Path socketPath) throws IOException {
    Files.deleteIfExists(socketPath);
    ServerSocketChannel serverSocket = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
    serverSocket.bind(UnixDomainSocketAddress.of(socketPath));

    LocalVaultProxy proxy =
        new LocalVaultProxy("unix://" + socketPath.toAbsolutePath(), serverSocket, socketPath);
    proxy.executor.submit(() -> proxy.serveUnix(serverSocket));
    return proxy;
  }

  private LocalVaultProxy(String uri, Closeable server, Path socketPath) {
    this.uri = uri;
    this.server = server;
    this.socketPath = socketPath;
    this.executor = Executors.newSingleThreadExecutor();
    this.requests = new CopyOnWriteArrayList<>();
  }

  String uri() {
    return uri;
  }

  List<Request> requests() {
    return requests;
  }

  private void serveTcp(ServerSocket serverSocket) {
    while (!closed) {
      try (Socket socket = serverSocket.accept()) {
        handle(socket.getInputStream(), socket.getOutputStream());
      } catch (SocketException e) {
        if (!closed) {
          throw new RuntimeException(e);
        }
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    }
  }

  private void serveUnix(ServerSocketChannel serverSocket) {
    while (!closed) {
      try (SocketChannel channel = serverSocket.accept()) {
        handle(Channels.newInputStream(channel), Channels.newOutputStream(channel));
      } catch (IOException e) {
        if (!closed) {
          throw new RuntimeException(e);
        }
      }
    }
  }

  private void handle(InputStream input, OutputStream output) throws IOException {
    Request request = readRequest(input);
    requests.add(request);

    byte[] responseBody = responseBody(request).getBytes(StandardCharsets.UTF_8);
    String header =
        "HTTP/1.1 200 OK\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: "
            + responseBody.length
            + "\r\n"
            + "Connection: close\r\n"
            + "\r\n";

    output.write(header.getBytes(StandardCharsets.US_ASCII));
    output.write(responseBody);
    output.flush();
  }

  private static Request readRequest(InputStream input) throws IOException {
    String headerText =
        new String(
            Http1MessageIO.readHeaderSection(
                input, "Local Vault proxy received an incomplete HTTP request"),
            StandardCharsets.US_ASCII);
    List<String> lines = List.of(headerText.split("\r\n"));
    String path = lines.get(0).split(" ", 3)[1];

    Map<String, String> headers = new HashMap<>();
    for (int index = 1; index < lines.size(); index++) {
      int separator = lines.get(index).indexOf(':');
      if (separator > 0) {
        headers.put(
            lines.get(index).substring(0, separator).toLowerCase(Locale.ROOT),
            lines.get(index).substring(separator + 1).trim());
      }
    }

    int contentLength = Integer.parseInt(headers.getOrDefault("content-length", "0"));
    byte[] body =
        Http1MessageIO.readFixed(
            input,
            contentLength,
            "Local Vault proxy request ended before reading Content-Length");
    return new Request(path, headers, new String(body, StandardCharsets.UTF_8));
  }

  private static String responseBody(Request request) throws IOException {
    JsonNode json = MAPPER.readTree(request.body());
    ObjectNode response = MAPPER.createObjectNode();
    ObjectNode data = response.putObject("data");

    if (request.path().contains("/encrypt/")) {
      data.put("ciphertext", CIPHERTEXT_PREFIX + json.get("plaintext").asText());
    } else if (request.path().contains("/decrypt/")) {
      String ciphertext = json.get("ciphertext").asText();
      data.put("plaintext", ciphertext.substring(CIPHERTEXT_PREFIX.length()));
    } else {
      throw new IllegalArgumentException("Unexpected path: " + request.path());
    }

    return MAPPER.writeValueAsString(response);
  }

  @Override
  public void close() throws IOException {
    closed = true;
    server.close();
    executor.shutdownNow();
    if (socketPath != null) {
      Files.deleteIfExists(socketPath);
    }
  }

  record Request(String path, Map<String, String> headers, String body) {}
}
