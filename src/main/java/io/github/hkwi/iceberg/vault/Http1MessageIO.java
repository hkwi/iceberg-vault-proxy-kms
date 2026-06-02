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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Minimal HTTP/1 message I/O for Unix domain socket transport.
 *
 * <p>HTTP(S) endpoints use the JDK HTTP stack, but Unix domain sockets are raw sockets here and
 * need explicit header terminator and body length handling.
 */
final class Http1MessageIO {
  private static final byte[] HEADER_TERMINATOR = {'\r', '\n', '\r', '\n'};
  private static final byte[] LINE_TERMINATOR = {'\r', '\n'};

  private Http1MessageIO() {}

  static byte[] readHeaderSection(InputStream input, String incompleteMessage) throws IOException {
    return readUntilTerminator(input, HEADER_TERMINATOR, incompleteMessage);
  }

  static String readAsciiLine(InputStream input, String incompleteMessage) throws IOException {
    return new String(
        readUntilTerminator(input, LINE_TERMINATOR, incompleteMessage), StandardCharsets.US_ASCII);
  }

  static byte[] readFixed(InputStream input, int length, String incompleteMessage)
      throws IOException {
    byte[] body = input.readNBytes(length);
    if (body.length != length) {
      throw new IOException(incompleteMessage);
    }

    return body;
  }

  private static byte[] readUntilTerminator(
      InputStream input, byte[] terminator, String incompleteMessage) throws IOException {
    ByteArrayOutputStream bytesWithTerminator = new ByteArrayOutputStream();
    int matchedTerminatorBytes = 0;
    int currentByte;
    while ((currentByte = input.read()) >= 0) {
      bytesWithTerminator.write(currentByte);

      if (currentByte == terminator[matchedTerminatorBytes]) {
        matchedTerminatorBytes++;
        if (matchedTerminatorBytes == terminator.length) {
          byte[] bytes = bytesWithTerminator.toByteArray();
          return Arrays.copyOf(bytes, bytes.length - terminator.length);
        }
      } else {
        matchedTerminatorBytes = currentByte == terminator[0] ? 1 : 0;
      }
    }

    throw new IOException(incompleteMessage);
  }
}
