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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

class VaultProxySslContext {
  private static final char[] EMPTY_PASSWORD = new char[0];
  private static final String PEM_TYPE = "PEM";
  private static final String PEM_CERTIFICATE = "CERTIFICATE";
  private static final String PEM_PRIVATE_KEY = "PRIVATE KEY";
  private static final String PEM_ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";
  private static final String PEM_RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
  private static final String[] PKCS8_PRIVATE_KEY_ALGORITHMS = {"RSA", "EC", "Ed25519", "Ed448"};
  private static final Pattern PEM_BLOCK_PATTERN =
      Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----\\s*(.*?)\\s*-----END \\1-----", Pattern.DOTALL);

  private VaultProxySslContext() {}

  static SSLSocketFactory sslSocketFactory(Map<String, String> properties) {
    SslInputs inputs = SslInputs.from(properties);

    if (!inputs.configured()) {
      return null;
    }

    inputs.validate();

    List<Path> reloadableFiles = reloadableFiles(properties, inputs);
    try {
      SSLSocketFactory socketFactory = buildSocketFactory(properties, inputs);
      if (reloadableFiles.isEmpty()) {
        return socketFactory;
      }

      return new ReloadingSslSocketFactory(properties, inputs, reloadableFiles, socketFactory);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to create Vault proxy SSL context", e);
    }
  }

  private static SSLSocketFactory buildSocketFactory(
      Map<String, String> properties, SslInputs inputs) throws GeneralSecurityException {
    KeyManager[] keyManagers = keyManagers(properties, inputs);
    TrustManager[] trustManagers = trustManagers(properties, inputs);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keyManagers, trustManagers, null);
    return context.getSocketFactory();
  }

  private static List<Path> reloadableFiles(Map<String, String> properties, SslInputs inputs) {
    List<Path> files = new ArrayList<>();
    if (inputs.hasKeyStoreLocation()) {
      files.add(Path.of(properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION)));
    }

    if (inputs.hasTrustStoreLocation()) {
      files.add(Path.of(properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION)));
    }

    return files;
  }

  private static List<FileTime> fileTimes(List<Path> files) {
    List<FileTime> times = new ArrayList<>();
    for (Path file : files) {
      try {
        times.add(Files.getLastModifiedTime(file));
      } catch (IOException e) {
        throw new UncheckedIOException("Failed to read TLS material timestamp " + file, e);
      }
    }

    return times;
  }

  private static KeyManager[] keyManagers(Map<String, String> properties, SslInputs inputs)
      throws GeneralSecurityException {
    if (inputs.hasKeyStore()) {
      return keyManagers(properties);
    } else if (inputs.hasPemKey()) {
      return pemKeyManagers(properties);
    }

    return null;
  }

  private static KeyManager[] keyManagers(Map<String, String> properties)
      throws GeneralSecurityException {
    char[] keyStorePassword =
        password(
            properties,
            VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_PASSWORD,
            VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_PASSWORD_ENV);
    char[] keyPassword =
        password(
            properties,
            VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD,
            VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD_ENV);
    try {
      KeyStore keyStore =
          loadKeyStore(
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION),
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE),
              keyStorePassword);
      if (keyPassword == null && keyStorePassword != null) {
        keyPassword = keyStorePassword.clone();
      }

      KeyManagerFactory factory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(keyStore, keyPassword);
      return factory.getKeyManagers();
    } finally {
      SensitiveMemory.zero(keyStorePassword);
      SensitiveMemory.zero(keyPassword);
    }
  }

  private static KeyManager[] pemKeyManagers(Map<String, String> properties)
      throws GeneralSecurityException {
    List<Certificate> certificates = keyStoreCertificates(properties);
    char[] keyPassword =
        password(
            properties,
            VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD,
            VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD_ENV);
    try {
      PrivateKey privateKey = keyStorePrivateKey(properties, keyPassword);
      char[] keyEntryPassword = keyPassword == null ? EMPTY_PASSWORD : keyPassword;

      KeyStore keyStore = emptyKeyStore();
      keyStore.setKeyEntry(
          "vault-proxy-client",
          privateKey,
          keyEntryPassword,
          certificates.toArray(new Certificate[0]));

      KeyManagerFactory factory =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(keyStore, keyEntryPassword);
      return factory.getKeyManagers();
    } finally {
      SensitiveMemory.zero(keyPassword);
    }
  }

  private static TrustManager[] trustManagers(Map<String, String> properties, SslInputs inputs)
      throws GeneralSecurityException {
    if (inputs.hasTrustStore()) {
      return trustManagers(properties);
    } else if (inputs.hasCaCertificate()) {
      return pemTrustManagers(properties);
    }

    return null;
  }

  private static TrustManager[] trustManagers(Map<String, String> properties)
      throws GeneralSecurityException {
    char[] trustStorePassword =
        password(
            properties,
            VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD,
            VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD_ENV);
    try {
      KeyStore trustStore =
          loadKeyStore(
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION),
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE),
              trustStorePassword);

      TrustManagerFactory factory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      factory.init(trustStore);
      return factory.getTrustManagers();
    } finally {
      SensitiveMemory.zero(trustStorePassword);
    }
  }

  private static TrustManager[] pemTrustManagers(Map<String, String> properties)
      throws GeneralSecurityException {
    List<Certificate> certificates = trustStoreCertificates(properties);
    KeyStore trustStore = emptyKeyStore();
    for (int i = 0; i < certificates.size(); i++) {
      trustStore.setCertificateEntry("vault-proxy-ca-" + i, certificates.get(i));
    }

    TrustManagerFactory factory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    factory.init(trustStore);
    return factory.getTrustManagers();
  }

  private static List<Certificate> keyStoreCertificates(Map<String, String> properties)
      throws GeneralSecurityException {
    String certificateChain =
        properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN);
    if (!isNullOrEmpty(certificateChain)) {
      return certificates(
          certificateChain, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN);
    }

    String location = properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION);
    return certificates(readPemFile(location), location);
  }

  private static PrivateKey keyStorePrivateKey(Map<String, String> properties, char[] keyPassword)
      throws GeneralSecurityException {
    String key = properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY);
    if (!isNullOrEmpty(key)) {
      return privateKey(key, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY, keyPassword);
    }

    String location = properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION);
    return privateKey(readPemFile(location), location, keyPassword);
  }

  private static List<Certificate> trustStoreCertificates(Map<String, String> properties)
      throws GeneralSecurityException {
    String certificates =
        properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES);
    if (!isNullOrEmpty(certificates)) {
      return certificates(
          certificates, VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES);
    }

    String location = properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION);
    return certificates(readPemFile(location), location);
  }

  private static KeyStore loadKeyStore(String location, String type, char[] password)
      throws GeneralSecurityException {
    String keyStoreType = isNullOrEmpty(type) ? KeyStore.getDefaultType() : type;
    KeyStore keyStore = KeyStore.getInstance(keyStoreType);
    try (InputStream input = Files.newInputStream(Path.of(location))) {
      keyStore.load(input, password);
      return keyStore;
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to load key store " + location, e);
    }
  }

  private static KeyStore emptyKeyStore() throws GeneralSecurityException {
    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    try {
      keyStore.load(null, null);
      return keyStore;
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to create in-memory key store", e);
    }
  }

  private static List<Certificate> certificates(String pem, String source)
      throws GeneralSecurityException {
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    List<Certificate> certificates = new ArrayList<>();
    for (PemBlock block : pemBlocks(pem, source)) {
      if (PEM_CERTIFICATE.equals(block.type())) {
        byte[] contents = block.contents();
        try (ByteArrayInputStream input = new ByteArrayInputStream(contents)) {
          certificates.add(factory.generateCertificate(input));
        } catch (IOException e) {
          throw new UncheckedIOException("Failed to read certificate PEM " + source, e);
        } finally {
          SensitiveMemory.zero(contents);
        }
      }
    }

    if (certificates.isEmpty()) {
      throw new IllegalArgumentException("No CERTIFICATE PEM block found in " + source);
    }

    return certificates;
  }

  private static PrivateKey privateKey(String pem, String source, char[] keyPassword)
      throws GeneralSecurityException {
    for (PemBlock block : pemBlocks(pem, source)) {
      byte[] contents = block.contents();
      if (PEM_PRIVATE_KEY.equals(block.type())) {
        try {
          return privateKeyFromPkcs8(contents);
        } finally {
          SensitiveMemory.zero(contents);
        }
      } else if (PEM_ENCRYPTED_PRIVATE_KEY.equals(block.type())) {
        try {
          return privateKeyFromEncryptedPkcs8(contents, keyPassword, source);
        } finally {
          SensitiveMemory.zero(contents);
        }
      } else if (PEM_RSA_PRIVATE_KEY.equals(block.type())) {
        try {
          return privateKeyFromPkcs1Rsa(contents);
        } finally {
          SensitiveMemory.zero(contents);
        }
      }
    }

    throw new IllegalArgumentException(
        "No PRIVATE KEY or RSA PRIVATE KEY PEM block found in " + source);
  }

  private static PrivateKey privateKeyFromPkcs8(byte[] keyBytes) throws GeneralSecurityException {
    try {
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      GeneralSecurityException failure = null;
      for (String algorithm : PKCS8_PRIVATE_KEY_ALGORITHMS) {
        try {
          return KeyFactory.getInstance(algorithm).generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
          if (failure == null) {
            failure = e;
          } else {
            failure.addSuppressed(e);
          }
        }
      }

      throw new GeneralSecurityException("Unsupported PKCS#8 private key algorithm", failure);
    } finally {
      SensitiveMemory.zero(keyBytes);
    }
  }

  private static PrivateKey privateKeyFromEncryptedPkcs8(
      byte[] keyBytes, char[] keyPassword, String source) throws GeneralSecurityException {
    if (keyPassword == null) {
      throw new IllegalArgumentException(
          "Encrypted PEM private key requires "
              + VaultProxyProperties.VAULT_PROXY_SSL_KEY_PASSWORD);
    }

    EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = newEncryptedPrivateKeyInfo(keyBytes, source);
    SecretKeyFactory secretKeyFactory =
        SecretKeyFactory.getInstance(encryptedPrivateKeyInfo.getAlgName());
    PBEKeySpec keySpec = new PBEKeySpec(keyPassword);
    SecretKey secretKey;
    try {
      secretKey = secretKeyFactory.generateSecret(keySpec);
    } finally {
      keySpec.clearPassword();
    }
    Cipher cipher = Cipher.getInstance(encryptedPrivateKeyInfo.getAlgName());
    cipher.init(Cipher.DECRYPT_MODE, secretKey, encryptedPrivateKeyInfo.getAlgParameters());
    return privateKeyFromPkcs8(encryptedPrivateKeyInfo.getKeySpec(cipher).getEncoded());
  }

  private static EncryptedPrivateKeyInfo newEncryptedPrivateKeyInfo(byte[] keyBytes, String source)
      throws GeneralSecurityException {
    try {
      return new EncryptedPrivateKeyInfo(keyBytes);
    } catch (IOException e) {
      throw new GeneralSecurityException(
          "Failed to parse encrypted PKCS#8 private key " + source, e);
    }
  }

  private static PrivateKey privateKeyFromPkcs1Rsa(byte[] keyBytes)
      throws GeneralSecurityException {
    EncodedPrivateKey encodedKey = new EncodedPrivateKey("RSA", "PKCS#1", keyBytes);
    try {
      return (PrivateKey) KeyFactory.getInstance("RSA").translateKey(encodedKey);
    } finally {
      encodedKey.clear();
      SensitiveMemory.zero(keyBytes);
    }
  }

  private static String readPemFile(String location) {
    try {
      return Files.readString(Path.of(location), StandardCharsets.US_ASCII);
    } catch (IOException e) {
      throw new UncheckedIOException("Failed to read PEM file " + location, e);
    }
  }

  private static List<PemBlock> pemBlocks(String pem, String source) {
    List<PemBlock> blocks = new ArrayList<>();
    Matcher matcher = PEM_BLOCK_PATTERN.matcher(pem);
    while (matcher.find()) {
      String type = matcher.group(1);
      String base64 = matcher.group(2).replaceAll("\\s", "");
      try {
        blocks.add(new PemBlock(type, Base64.getDecoder().decode(base64)));
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Invalid PEM block in " + source, e);
      }
    }

    if (blocks.isEmpty()) {
      throw new IllegalArgumentException("No PEM blocks found in " + source);
    }

    return blocks;
  }

  private static boolean configured(Map<String, String> properties, String property) {
    return !isNullOrEmpty(properties.get(property));
  }

  private static char[] password(
      Map<String, String> properties, String passwordProperty, String passwordEnvProperty) {
    String envVar = properties.get(passwordEnvProperty);
    if (!isNullOrEmpty(envVar)) {
      String value = System.getenv(envVar);
      return value != null ? value.toCharArray() : null;
    }

    String value = properties.get(passwordProperty);
    return value != null ? value.toCharArray() : null;
  }

  private static boolean isNullOrEmpty(String value) {
    return value == null || value.isEmpty();
  }

  private static class ReloadingSslSocketFactory extends SSLSocketFactory {
    private final Map<String, String> properties;
    private final SslInputs inputs;
    private final List<Path> files;

    private volatile SSLSocketFactory delegate;
    private volatile List<FileTime> fileTimes;

    ReloadingSslSocketFactory(
        Map<String, String> properties,
        SslInputs inputs,
        List<Path> files,
        SSLSocketFactory delegate) {
      this.properties = Map.copyOf(properties);
      this.inputs = inputs;
      this.files = List.copyOf(files);
      this.delegate = delegate;
      this.fileTimes = fileTimes(files);
    }

    @Override
    public String[] getDefaultCipherSuites() {
      return delegate().getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
      return delegate().getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
      return delegate().createSocket();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
      return delegate().createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort)
        throws IOException {
      return delegate().createSocket(host, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
      return delegate().createSocket(host, port);
    }

    @Override
    public Socket createSocket(
        InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
      return delegate().createSocket(address, port, localAddress, localPort);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClose)
        throws IOException {
      return delegate().createSocket(socket, host, port, autoClose);
    }

    @Override
    public Socket createSocket(Socket socket, InputStream consumed, boolean autoClose)
        throws IOException {
      return delegate().createSocket(socket, consumed, autoClose);
    }

    private SSLSocketFactory delegate() {
      try {
        List<FileTime> currentFileTimes = fileTimes(files);
        if (!currentFileTimes.equals(fileTimes)) {
          reload(currentFileTimes);
        }

        return delegate;
      } catch (GeneralSecurityException | RuntimeException e) {
        throw new RuntimeException("Failed to reload Vault proxy SSL context", e);
      }
    }

    private synchronized void reload(List<FileTime> currentFileTimes)
        throws GeneralSecurityException {
      if (!currentFileTimes.equals(fileTimes)) {
        delegate = buildSocketFactory(properties, inputs);
        fileTimes = currentFileTimes;
      }
    }
  }

  private static class EncodedPrivateKey implements PrivateKey {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final String format;
    private final byte[] encoded;

    EncodedPrivateKey(String algorithm, String format, byte[] encoded) {
      this.algorithm = algorithm;
      this.format = format;
      this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
      return algorithm;
    }

    @Override
    public String getFormat() {
      return format;
    }

    @Override
    public byte[] getEncoded() {
      return encoded.clone();
    }

    void clear() {
      SensitiveMemory.zero(encoded);
    }
  }

  private static class SslInputs {
    private final boolean hasKeyStoreLocation;
    private final boolean hasKeyStoreType;
    private final boolean keyStoreTypePem;
    private final boolean hasKeyStoreKey;
    private final boolean hasKeyStoreCertificateChain;
    private final boolean hasTrustStoreLocation;
    private final boolean hasTrustStoreType;
    private final boolean trustStoreTypePem;
    private final boolean hasTrustStoreCertificates;

    static SslInputs from(Map<String, String> properties) {
      return new SslInputs(
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE),
          PEM_TYPE.equalsIgnoreCase(
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE)),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE),
          PEM_TYPE.equalsIgnoreCase(
              properties.get(VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE)),
          VaultProxySslContext.configured(
              properties, VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES));
    }

    SslInputs(
        boolean hasKeyStoreLocation,
        boolean hasKeyStoreType,
        boolean keyStoreTypePem,
        boolean hasKeyStoreKey,
        boolean hasKeyStoreCertificateChain,
        boolean hasTrustStoreLocation,
        boolean hasTrustStoreType,
        boolean trustStoreTypePem,
        boolean hasTrustStoreCertificates) {
      this.hasKeyStoreLocation = hasKeyStoreLocation;
      this.hasKeyStoreType = hasKeyStoreType;
      this.keyStoreTypePem = keyStoreTypePem;
      this.hasKeyStoreKey = hasKeyStoreKey;
      this.hasKeyStoreCertificateChain = hasKeyStoreCertificateChain;
      this.hasTrustStoreLocation = hasTrustStoreLocation;
      this.hasTrustStoreType = hasTrustStoreType;
      this.trustStoreTypePem = trustStoreTypePem;
      this.hasTrustStoreCertificates = hasTrustStoreCertificates;
    }

    boolean configured() {
      return hasKeyStore() || hasPemKey() || hasTrustStore() || hasCaCertificate();
    }

    void validate() {
      validateKeyConfiguration();
      validateTrustConfiguration();
    }

    boolean hasKeyStore() {
      return hasKeyStoreLocation && !keyStoreTypePem;
    }

    boolean hasKeyStoreLocation() {
      return hasKeyStoreLocation;
    }

    boolean hasPemKey() {
      return (hasKeyStoreLocation && keyStoreTypePem)
          || hasKeyStoreKey
          || hasKeyStoreCertificateChain;
    }

    boolean hasTrustStore() {
      return hasTrustStoreLocation && !trustStoreTypePem;
    }

    boolean hasTrustStoreLocation() {
      return hasTrustStoreLocation;
    }

    boolean hasCaCertificate() {
      return (hasTrustStoreLocation && trustStoreTypePem) || hasTrustStoreCertificates;
    }

    private void validateKeyConfiguration() {
      if (hasKeyStoreLocation && (hasKeyStoreKey || hasKeyStoreCertificateChain)) {
        throw new IllegalArgumentException(
            "Configure either "
                + VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_LOCATION
                + " or inline PEM key store material");
      }

      if (hasKeyStoreType && !keyStoreTypePem && (hasKeyStoreKey || hasKeyStoreCertificateChain)) {
        throw new IllegalArgumentException(
            "Inline PEM key store material requires "
                + VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_TYPE
                + "=PEM or no explicit key store type");
      }

      if ((hasKeyStoreKey || hasKeyStoreCertificateChain)
          && (!hasKeyStoreKey || !hasKeyStoreCertificateChain)) {
        throw new IllegalArgumentException(
            "PEM client authentication requires both "
                + VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN
                + " and "
                + VaultProxyProperties.VAULT_PROXY_SSL_KEYSTORE_KEY);
      }
    }

    private void validateTrustConfiguration() {
      if (hasTrustStoreLocation && hasTrustStoreCertificates) {
        throw new IllegalArgumentException(
            "Configure either "
                + VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_LOCATION
                + " or "
                + VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES);
      }

      if (hasTrustStoreType && !trustStoreTypePem && hasTrustStoreCertificates) {
        throw new IllegalArgumentException(
            "Inline PEM trust store material requires "
                + VaultProxyProperties.VAULT_PROXY_SSL_TRUSTSTORE_TYPE
                + "=PEM or no explicit trust store type");
      }
    }
  }

  private record PemBlock(String type, byte[] contents) {}
}
