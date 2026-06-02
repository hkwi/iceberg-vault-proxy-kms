# Iceberg Vault Proxy KMS

This is an out-of-tree/private extension that implements Iceberg's
`KeyManagementClient` interface for a local Vault Proxy.

The extension is not registered in Apache Iceberg as an `encryption.kms-type`.
Put this jar on the runtime classpath and load it explicitly with
`encryption.kms-impl`.

## Usage

```sh
spark-sql \
  --packages org.apache.iceberg:iceberg-spark-runtime-4.1_2.13:${ICEBERG_VERSION},io.github.hkwi.iceberg:iceberg-vault-proxy-kms:${EXTENSION_VERSION} \
  --conf spark.sql.extensions=org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions \
  --conf spark.sql.catalog.local=org.apache.iceberg.spark.SparkCatalog \
  --conf spark.sql.catalog.local.type=hive \
  --conf spark.sql.catalog.local.encryption.kms-impl=io.github.hkwi.iceberg.vault.VaultProxyKeyManagementClient \
  --conf spark.sql.catalog.local.vault-proxy.uri=http://127.0.0.1:8200 \
  --conf spark.sql.catalog.local.vault-proxy.transit-path=transit \
  --conf spark.sql.catalog.local.vault-proxy.namespace=admin
```

## Options

| Property | Default | Description |
| --- | --- | --- |
| `vault-proxy.uri` | `http://127.0.0.1:8200` | Proxy endpoint. Supports `http://...`, `https://...`, and `unix:///path/to/socket`. |
| `vault-proxy.transit-path` | `transit` | Vault Transit compatible mount/path exposed by the proxy. |
| `vault-proxy.namespace` | | Value sent as `X-Vault-Namespace`. Vault authentication headers, such as Vault tokens, are not sent by this client and are delegated to the Vault Proxy. |
| `vault-proxy.connect-timeout-ms` | `5000` | Proxy connection timeout in milliseconds. |
| `vault-proxy.read-timeout-ms` | `30000` | Proxy read timeout in milliseconds. |
| `vault-proxy.ssl.keystore.location` | | Client key material file in JKS, PKCS12, or PEM format. |
| `vault-proxy.ssl.keystore.type` | JVM default | Key store type, such as `JKS`, `PKCS12`, or `PEM`. |
| `vault-proxy.ssl.keystore.password` | | Key store password. |
| `vault-proxy.ssl.keystore.password.env` | | Environment variable name that contains the key store password. Takes precedence over the direct password value. |
| `vault-proxy.ssl.key.password` | | Private key password. For Java key stores, this falls back to the key store password. For encrypted PEM keys, this value is used for private key decryption. |
| `vault-proxy.ssl.key.password.env` | | Environment variable name that contains the private key password. Takes precedence over the direct password value. |
| `vault-proxy.ssl.keystore.key` | | Inline PEM private key. |
| `vault-proxy.ssl.keystore.certificate.chain` | | Inline PEM certificate chain. |
| `vault-proxy.ssl.truststore.location` | | CA/trust material file in JKS, PKCS12, or PEM format. |
| `vault-proxy.ssl.truststore.type` | JVM default | Trust store type, such as `JKS`, `PKCS12`, or `PEM`. |
| `vault-proxy.ssl.truststore.password` | | Trust store password. |
| `vault-proxy.ssl.truststore.password.env` | | Environment variable name that contains the trust store password. Takes precedence over the direct password value. |
| `vault-proxy.ssl.truststore.certificates` | | Inline PEM CA certificates. |

For HTTPS, if no valid `vault-proxy.ssl.*` TLS material is configured, the
client does not install a dedicated `SSLSocketFactory`. In that case,
`HttpsURLConnection` uses the JVM default TLS configuration, including standard
`javax.net.ssl.*` system properties.

PEM private keys support unencrypted PKCS#8 `PRIVATE KEY`, encrypted PKCS#8
`ENCRYPTED PRIVATE KEY`, and unencrypted PKCS#1 RSA `RSA PRIVATE KEY` blocks.
Encrypted PKCS#1 RSA PEM keys are not supported, matching Kafka's default PEM
support.

For JKS, PKCS12, and PEM material loaded from `*.location`, the client checks
file timestamps before creating TLS sockets and reloads the SSL context after a
timestamp change. Inline PEM values are not reloadable because they have no file
timestamp.

## Sensitive Memory Handling

Java cannot provide the same process-wide `mlock` semantics as the Go
implementation without JNI/JNA. This client therefore keeps plaintext key bytes
out of heap-backed return buffers where possible and explicitly zeroes temporary
`byte[]` and `char[]` values after use.

`unwrapKey` returns a direct `ByteBuffer` for plaintext key material. Temporary
heap arrays used for Vault Transit base64 conversion, TLS store passwords, and
decoded PEM private key bytes are cleared in `finally` blocks. Catalog
properties and environment variables are still Java `String` values, so the
preferred production setup is a local Vault Proxy that owns Vault
authentication and avoids passing Vault tokens to this JVM.

## Development

When an Apache Iceberg worktree exists next to this project, Gradle uses a
composite build and resolves `org.apache.iceberg:iceberg-core` from that source
tree.

```sh
../iceberg-vault-proxy/gradlew -p . check
```
