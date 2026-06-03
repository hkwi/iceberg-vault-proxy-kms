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

import static io.github.hkwi.iceberg.vault.VaultProxyProperties.VAULT_PROXY_NAMESPACE;
import static io.github.hkwi.iceberg.vault.VaultProxyProperties.VAULT_PROXY_TRANSIT_PATH;
import static io.github.hkwi.iceberg.vault.VaultProxyProperties.VAULT_PROXY_URI;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.util.Map;
import javax.net.ssl.SSLSocketFactory;
import org.apache.iceberg.CatalogProperties;
import org.apache.iceberg.encryption.EncryptionUtil;
import org.apache.iceberg.encryption.KeyManagementClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TestVaultProxyKeyManagementClient {
  private static final String TEST_CERTIFICATE_PEM =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICBDCCAW2gAwIBAgIULsulXKY3Q6x3GgJuXrHubrkVCCQwDQYJKoZIhvcNAQEL\n"
          + "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYwMjAzNDUyNFoXDTI2MDYw\n"
          + "MzAzNDUyNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIGfMA0GCSqGSIb3DQEBAQUA\n"
          + "A4GNADCBiQKBgQCZNqPmKACHlMdb3oMiA5PI0KGDdX7Pojzy8iRRRapbxpDFTTxF\n"
          + "hdHZuTQa9eSgFVJFpMOBv2ozNViy6iUfHjttJHFTWsaiaK0b9eza21T82EizqtuM\n"
          + "6brLp7x1Ag0S3+MjPy9EbBj5CKSXz9SOnAkgdVUTmQZFbZIsuHEsQpisGQIDAQAB\n"
          + "o1MwUTAdBgNVHQ4EFgQUTZwZ7PdlriMo51OKBjVujTeo5OQwHwYDVR0jBBgwFoAU\n"
          + "TZwZ7PdlriMo51OKBjVujTeo5OQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n"
          + "AQsFAAOBgQBirqMhG1o40/UKM1kZWDmyXa+ZCRWrVg4UVnfFMydfUnMk0lsulXbn\n"
          + "Ur/5dtxyZvkVgaMfl9J1KpqrhLiVxgrC4INIwD+uU6ZemDOetGhXphmpkuJqmVNq\n"
          + "i5Zj2b94wIU+iS9wFZ1ylq+QaemRyQMZ7JCaT62b9t5IKF9pdQxkQw==\n"
          + "-----END CERTIFICATE-----\n";
  private static final String TEST_PKCS1_RSA_PRIVATE_KEY_PEM =
      "-----BEGIN RSA PRIVATE KEY-----\n"
          + "MIICXgIBAAKBgQCZNqPmKACHlMdb3oMiA5PI0KGDdX7Pojzy8iRRRapbxpDFTTxF\n"
          + "hdHZuTQa9eSgFVJFpMOBv2ozNViy6iUfHjttJHFTWsaiaK0b9eza21T82EizqtuM\n"
          + "6brLp7x1Ag0S3+MjPy9EbBj5CKSXz9SOnAkgdVUTmQZFbZIsuHEsQpisGQIDAQAB\n"
          + "AoGAG1mgqm5LoehSKjkvaXv//qIXovLvfzsz7B6Dkyp/fcCViVL/Rl3cFySzg3iP\n"
          + "pnAH7ry51ciIubl1KwMXO1XXP57A3hCNyxJ4d6STIo0G+Zz/PIIU76tDE/pt3XHa\n"
          + "6tqHqgYkhb2Zv1ug/gKqgtUAuqNxMMFC4rdoax3/+PYHwS0CQQDJgvU5OAe/moVM\n"
          + "SmeApjdyvVSHfEudcT2tGr2PHyhXjC/wqkFCunVphUZTjyTVR9Tu7x+a0hdr8wBO\n"
          + "NJBLWBzbAkEAwqRjTtWevyPUSDKsa2Oiq5IfR2cBv2pI/sVX9gomi7K78u45fhCG\n"
          + "37Bnv0NYaZyxpUGD0JvyFh9ZFt0ShgozGwJBAKLXEROME7biR5W/CqULrQMrvINA\n"
          + "DlrMh+q7ETP3GcKlppf0/YfO5dK/wHUF194CjjAHTKLv4714QWbxUymPqsECQQCG\n"
          + "nQRliE4S6WeuSwV9+9mMCTICwtWtmYdEVB2CdwCzivh7iZBPhISS/cCywZPK7ujZ\n"
          + "XtcYFlI2RJXrvxdJhpJTAkEApNr0daabM/QYtyccl5NqdBSK5AIvtopeXaoC8TMU\n"
          + "SBGjNQwweIgYwXpqXIzWP9iMm5V1RXfmU+RFGKZtPfsGOA==\n"
          + "-----END RSA PRIVATE KEY-----\n";
  private static final String TEST_ENCRYPTED_PKCS8_PRIVATE_KEY_PEM =
      "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
          + "MIICojAcBgoqhkiG9w0BDAEDMA4ECIHIpDHX5GTaAgIIAASCAoA9QkeFHQCn1+Jt\n"
          + "Gt3WbaZXiGth+dJ3aOKSZdhzuzxw9i3S88B53ybQ2ebOzNK/3XF4M63hkNwMZ5UD\n"
          + "DMAydbH5utma2sJE6l+s7mHFMUwrlz5lo8DQrVaauX2+0EQTaGqz7SNBqf0aKSpQ\n"
          + "o8ifSY4y9qUw8rGmau/TUiULwWJTCHVhCnMXQ8HxPYM1Y7YiWfRqJUflGulbDPcE\n"
          + "mfH8CIj2UompQOCYs78mXr2gx0VJMcxYfLl022MKX/QFLnGyOviegBMPh7Xy6EuW\n"
          + "eO1uB/UAv9R3BXttHXlZ0dn8HbV7kNg2wzJS/xMrjoumDc6gcZlnaq4cD7vEJuvu\n"
          + "xxUPLmSTkU/Z6xeTKI580eqIE2hoR/p8ddm0EIOgQTTJc2L1GBiAjXwM+fnUGwWS\n"
          + "DPT+hIuWtTvDFac7r6sgJr2fD9v5nBU7pDMVikEI1/q/pzXw26o/fzPrb98D3/A4\n"
          + "+vA5K3PuAuLpfBi77wcFgZMnvCxFzQ3R4RuEbU9HQCjhpcgVSf2QQxYK1l2+9rqT\n"
          + "8/XG3K/uoRkXuU5uKEkjbJfEe4dEOBxHraaKMjsaHLjA24NoFewKpg6V7WRwgVfs\n"
          + "ZMv4I7pne+fuotQT7DBALHZv4KC8+BKoK9vsW1iuSTsIHL4Q+F4IzbC3+swPy5S3\n"
          + "mu7wjGyxllJxyGC1NswbDRyfL/jy8N9ta4/ATb3LQ/HSJ6rRZMCAwLjLPlj8RKnO\n"
          + "pKhkgzzAINDj2AYVXyxSBAgPbuu6R/uiDfR1iOMhB846PHWINMu8YIctBZlgqpvl\n"
          + "rwAmd9zMntSKXMxGxrnRw8pjApDQKJbYD0o0uo1oj7kYJ7QYZLhtvdbiFfQQYW5n\n"
          + "WJtaWD25\n"
          + "-----END ENCRYPTED PRIVATE KEY-----\n";

  @TempDir private Path tempDir;

  @Test
  void doesNotBuildSslSocketFactoryWithoutExplicitTlsMaterial() {
    assertThat(VaultProxySslContext.sslSocketFactory(Map.of())).isNull();
    assertThat(
            VaultProxySslContext.sslSocketFactory(
                Map.of(
                    VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_PASSWORD,
                    "changeit",
                    VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE,
                    "PKCS12")))
        .isNull();
  }

  @Test
  void buildsSslSocketFactoryFromStores() throws Exception {
    Path keyStore = writeEmptyKeyStore("client.p12", "changeit");
    Path trustStore = writeEmptyKeyStore("trust.p12", "changeit");

    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION,
                keyStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE,
                "PKCS12",
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_PASSWORD,
                "changeit",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION,
                trustStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE,
                "PKCS12",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD,
                "changeit"));

    assertThat(socketFactory).isNotNull();
  }

  @Test
  void reloadsSslSocketFactoryWhenStoreTimestampChanges() throws Exception {
    Path keyStore = writeEmptyKeyStore("reload-client.p12", "changeit");
    Path trustStore = writeEmptyKeyStore("reload-trust.p12", "changeit");

    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION,
                keyStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE,
                "PKCS12",
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_PASSWORD,
                "changeit",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION,
                trustStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE,
                "PKCS12",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD,
                "changeit"));

    assertThat(socketFactory.getDefaultCipherSuites()).isNotEmpty();

    Files.writeString(keyStore, "not a key store", StandardCharsets.US_ASCII);
    Files.setLastModifiedTime(keyStore, futureFileTime());

    assertThatThrownBy(() -> socketFactory.getDefaultCipherSuites())
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("Failed to reload Vault proxy SSL context");
  }

  @Test
  void buildsSslSocketFactoryFromPemFilesWithPkcs1RsaPrivateKey() throws Exception {
    Path keyStore = writePem("client.pem", TEST_CERTIFICATE_PEM + TEST_PKCS1_RSA_PRIVATE_KEY_PEM);
    Path trustStore = writePem("truststore.pem", TEST_CERTIFICATE_PEM);

    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION,
                keyStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE,
                "PEM",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION,
                trustStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE,
                "PEM"));

    assertThat(socketFactory).isNotNull();
  }

  @Test
  void reloadsSslSocketFactoryWhenPemTimestampChanges() throws Exception {
    Path keyStore =
        writePem("reload-client.pem", TEST_CERTIFICATE_PEM + TEST_PKCS1_RSA_PRIVATE_KEY_PEM);
    Path trustStore = writePem("reload-truststore.pem", TEST_CERTIFICATE_PEM);

    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION,
                keyStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE,
                "PEM",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION,
                trustStore.toString(),
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE,
                "PEM"));

    assertThat(socketFactory.getDefaultCipherSuites()).isNotEmpty();

    Files.writeString(keyStore, TEST_CERTIFICATE_PEM, StandardCharsets.US_ASCII);
    Files.setLastModifiedTime(keyStore, futureFileTime());

    assertThatThrownBy(() -> socketFactory.getDefaultCipherSuites())
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("Failed to reload Vault proxy SSL context");
  }

  @Test
  void buildsSslSocketFactoryFromInlinePemWithPkcs1RsaPrivateKey() {
    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN,
                TEST_CERTIFICATE_PEM,
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY,
                TEST_PKCS1_RSA_PRIVATE_KEY_PEM,
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES,
                TEST_CERTIFICATE_PEM));

    assertThat(socketFactory).isNotNull();
  }

  @Test
  void buildsSslSocketFactoryFromInlineEncryptedPkcs8PrivateKey() {
    SSLSocketFactory socketFactory =
        VaultProxySslContext.sslSocketFactory(
            Map.of(
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN,
                TEST_CERTIFICATE_PEM,
                VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY,
                TEST_ENCRYPTED_PKCS8_PRIVATE_KEY_PEM,
                VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD,
                "changeit",
                VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES,
                TEST_CERTIFICATE_PEM));

    assertThat(socketFactory).isNotNull();
  }

  @Test
  void rejectsEncryptedPemPrivateKeyWithoutKeyPassword() {
    assertThatThrownBy(
            () ->
                VaultProxySslContext.sslSocketFactory(
                    Map.of(
                        VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN,
                        TEST_CERTIFICATE_PEM,
                        VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY,
                        TEST_ENCRYPTED_PKCS8_PRIVATE_KEY_PEM)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD);
  }

  @Test
  void rejectsPartialPemClientAuthentication() {
    assertThatThrownBy(
            () ->
                VaultProxySslContext.sslSocketFactory(
                    Map.of(
                        VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN,
                        TEST_CERTIFICATE_PEM)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY);
  }

  @Test
  void encryptionUtilCreatesVaultProxyClientFromKmsImpl() throws Exception {
    try (KeyManagementClient client =
        EncryptionUtil.createKmsClient(
            Map.of(
                CatalogProperties.ENCRYPTION_KMS_IMPL,
                VaultProxyKeyManagementClient.class.getName()))) {
      assertThat(client).isInstanceOf(VaultProxyKeyManagementClient.class);
    }
  }

  @Test
  void wrapAndUnwrapOverLocalHttpProxy() throws Exception {
    try (LocalVaultProxy proxy = LocalVaultProxy.tcp();
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(
          Map.of(
              VAULT_PROXY_URI,
              proxy.uri(),
              VAULT_PROXY_TRANSIT_PATH,
              "team/transit",
              VAULT_PROXY_NAMESPACE,
              "admin"));

      ByteBuffer key = ByteBuffer.wrap("secret-key".getBytes(StandardCharsets.UTF_8));
      ByteBuffer wrapped = client.wrapKey(key, "table-key");
      ByteBuffer unwrapped = client.unwrapKey(wrapped, "table-key");

      assertThat(unwrapped.isDirect()).isTrue();
      assertThat(unwrapped).isEqualTo(key);
      assertThat(proxy.requests())
          .extracting(LocalVaultProxy.Request::path)
          .containsExactly(
              "/v1/team/transit/encrypt/table-key", "/v1/team/transit/decrypt/table-key");
      assertThat(proxy.requests())
          .allSatisfy(
              request -> {
                assertThat(request.headers()).containsEntry("x-vault-namespace", "admin");
                assertThat(request.headers()).doesNotContainKey("x-vault-token");
              });
    }
  }

  @Test
  void sendsConfiguredVendedBearerTokenToProxy() throws Exception {
    try (LocalVaultProxy proxy = LocalVaultProxy.tcp();
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(
          Map.of(
              VAULT_PROXY_URI,
              proxy.uri(),
              VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN,
              "initial-vault-proxy-token",
              VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN_EXPIRES_AT_MS,
              String.valueOf(System.currentTimeMillis() + 3_600_000L)));

      ByteBuffer key = ByteBuffer.wrap("secret-key".getBytes(StandardCharsets.UTF_8));
      client.wrapKey(key, "table-key");

      assertThat(proxy.requests()).hasSize(1);
      assertThat(proxy.requests().get(0).headers())
          .containsEntry("authorization", "Bearer initial-vault-proxy-token")
          .doesNotContainKey("x-vault-token");
    }
  }

  @Test
  void sendsConfiguredTokenWithoutSchemeToProxy() throws Exception {
    try (LocalVaultProxy proxy = LocalVaultProxy.tcp();
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(
          Map.of(
              VAULT_PROXY_URI,
              proxy.uri(),
              VaultProxyProperties.VAULT_PROXY_AUTH_TOKEN,
              "scheme-less-vault-proxy-token",
              VaultProxyProperties.VAULT_PROXY_AUTH_SCHEME,
              ""));

      ByteBuffer key = ByteBuffer.wrap("secret-key".getBytes(StandardCharsets.UTF_8));
      client.wrapKey(key, "table-key");

      assertThat(proxy.requests().get(0).headers())
          .containsEntry("authorization", "scheme-less-vault-proxy-token");
    }
  }

  @Test
  void refreshesVendedBearerTokenFromRestCredentialsEndpoint() throws Exception {
    try (LocalVaultProxy proxy = LocalVaultProxy.tcp();
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(
          Map.of(
              VAULT_PROXY_URI,
              proxy.uri(),
              CatalogProperties.URI,
              proxy.uri(),
              VaultProxyProperties.VAULT_PROXY_AUTH_REFRESH_CREDENTIALS_ENDPOINT,
              "/credentials"));

      ByteBuffer key = ByteBuffer.wrap("secret-key".getBytes(StandardCharsets.UTF_8));
      client.wrapKey(key, "table-key");

      assertThat(proxy.requests())
          .extracting(request -> request.method() + " " + request.path())
          .containsExactly("GET /credentials", "POST /v1/transit/encrypt/table-key");
      assertThat(proxy.requests().get(1).headers())
          .containsEntry("authorization", "Bearer refreshed-vault-proxy-token")
          .doesNotContainKey("x-vault-token");
    }
  }

  @Test
  void doesNotLoadSslMaterialForNonHttpsProxy() throws Exception {
    try (LocalVaultProxy proxy = LocalVaultProxy.tcp();
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(
          Map.of(
              VAULT_PROXY_URI,
              proxy.uri(),
              VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION,
              tempDir.resolve("missing.p12").toString()));

      ByteBuffer key = ByteBuffer.wrap("http-secret-key".getBytes(StandardCharsets.UTF_8));
      ByteBuffer wrapped = client.wrapKey(key, "table-key");
      ByteBuffer unwrapped = client.unwrapKey(wrapped, "table-key");

      assertThat(unwrapped.isDirect()).isTrue();
      assertThat(unwrapped).isEqualTo(key);
    }
  }

  @Test
  void wrapAndUnwrapOverUnixDomainSocket() throws Exception {
    Path socketPath = tempDir.resolve("vault-proxy.sock");
    try (LocalVaultProxy proxy = LocalVaultProxy.unix(socketPath);
        KeyManagementClient client = new VaultProxyKeyManagementClient()) {
      client.initialize(Map.of(VAULT_PROXY_URI, proxy.uri()));

      ByteBuffer key = ByteBuffer.wrap("unix-secret-key".getBytes(StandardCharsets.UTF_8));
      ByteBuffer wrapped = client.wrapKey(key, "table-key");
      ByteBuffer unwrapped = client.unwrapKey(wrapped, "table-key");

      assertThat(unwrapped.isDirect()).isTrue();
      assertThat(unwrapped).isEqualTo(key);
      assertThat(proxy.requests())
          .extracting(LocalVaultProxy.Request::path)
          .containsExactly("/v1/transit/encrypt/table-key", "/v1/transit/decrypt/table-key");
      assertThat(proxy.requests())
          .allSatisfy(
              request -> {
                assertThat(request.headers()).containsEntry("host", "localhost");
                assertThat(request.headers()).doesNotContainKey("x-vault-token");
              });
    }
  }

  private Path writeEmptyKeyStore(String fileName, String password) throws Exception {
    Path path = tempDir.resolve(fileName);
    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, password.toCharArray());
    try (java.io.OutputStream output = java.nio.file.Files.newOutputStream(path)) {
      keyStore.store(output, password.toCharArray());
    }

    return path;
  }

  private Path writePem(String fileName, String pem) throws Exception {
    Path path = tempDir.resolve(fileName);
    Files.writeString(path, pem, StandardCharsets.US_ASCII);
    return path;
  }

  private static FileTime futureFileTime() {
    return FileTime.fromMillis(System.currentTimeMillis() + 60_000);
  }
}
