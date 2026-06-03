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

/** Catalog properties for Vault Proxy based KMS access. */
public final class VaultProxyProperties {
  public static final String VAULT_PROXY_URI = "vault-proxy.uri";
  public static final String VAULT_PROXY_URI_DEFAULT = "http://127.0.0.1:8200";

  public static final String VAULT_PROXY_TRANSIT_PATH = "vault-proxy.transit-path";
  public static final String VAULT_PROXY_TRANSIT_PATH_DEFAULT = "transit";

  public static final String VAULT_PROXY_NAMESPACE = "vault-proxy.namespace";

  public static final String VAULT_PROXY_AUTH_TOKEN = "vault-proxy.auth.token";
  public static final String VAULT_PROXY_AUTH_TOKEN_EXPIRES_AT_MS =
      "vault-proxy.auth.token-expires-at-ms";
  public static final String VAULT_PROXY_AUTH_REFRESH_CREDENTIALS_ENDPOINT =
      "vault-proxy.auth.refresh-credentials-endpoint";
  public static final String VAULT_PROXY_AUTH_CREDENTIAL_PREFIX =
      "vault-proxy.auth.credential-prefix";
  public static final String VAULT_PROXY_AUTH_CREDENTIAL_PREFIX_DEFAULT = "vault-proxy";
  public static final String VAULT_PROXY_AUTH_HEADER = "vault-proxy.auth.header";
  public static final String VAULT_PROXY_AUTH_HEADER_DEFAULT = "Authorization";
  public static final String VAULT_PROXY_AUTH_SCHEME = "vault-proxy.auth.scheme";
  public static final String VAULT_PROXY_AUTH_SCHEME_DEFAULT = "Bearer";
  public static final String VAULT_PROXY_AUTH_REFRESH_PREFETCH_MS =
      "vault-proxy.auth.refresh-prefetch-ms";
  public static final long VAULT_PROXY_AUTH_REFRESH_PREFETCH_MS_DEFAULT = 300_000L;

  public static final String VAULT_PROXY_CONNECT_TIMEOUT_MS = "vault-proxy.connect-timeout-ms";
  public static final int VAULT_PROXY_CONNECT_TIMEOUT_MS_DEFAULT = 5_000;

  public static final String VAULT_PROXY_READ_TIMEOUT_MS = "vault-proxy.read-timeout-ms";
  public static final int VAULT_PROXY_READ_TIMEOUT_MS_DEFAULT = 30_000;

  public static final String VAULT_PROXY_SSL_KEYSTORE_LOCATION =
      "vault-proxy.ssl.keystore.location";
  public static final String VAULT_PROXY_SSL_KEYSTORE_TYPE = "vault-proxy.ssl.keystore.type";
  public static final String VAULT_PROXY_SSL_KEYSTORE_PASSWORD =
      "vault-proxy.ssl.keystore.password";
  public static final String VAULT_PROXY_SSL_KEYSTORE_PASSWORD_ENV =
      "vault-proxy.ssl.keystore.password.env";
  public static final String VAULT_PROXY_SSL_KEY_PASSWORD = "vault-proxy.ssl.key.password";
  public static final String VAULT_PROXY_SSL_KEY_PASSWORD_ENV = "vault-proxy.ssl.key.password.env";
  public static final String VAULT_PROXY_SSL_KEYSTORE_KEY = "vault-proxy.ssl.keystore.key";
  public static final String VAULT_PROXY_SSL_KEYSTORE_CERTIFICATE_CHAIN =
      "vault-proxy.ssl.keystore.certificate.chain";

  public static final String VAULT_PROXY_SSL_TRUSTSTORE_LOCATION =
      "vault-proxy.ssl.truststore.location";
  public static final String VAULT_PROXY_SSL_TRUSTSTORE_TYPE = "vault-proxy.ssl.truststore.type";
  public static final String VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD =
      "vault-proxy.ssl.truststore.password";
  public static final String VAULT_PROXY_SSL_TRUSTSTORE_PASSWORD_ENV =
      "vault-proxy.ssl.truststore.password.env";
  public static final String VAULT_PROXY_SSL_TRUSTSTORE_CERTIFICATES =
      "vault-proxy.ssl.truststore.certificates";

  private VaultProxyProperties() {}
}
