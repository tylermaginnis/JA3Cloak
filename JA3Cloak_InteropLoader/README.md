# JA3Cloak InteropLoader

JA3Cloak InteropLoader is the .NET version of the JA3Cloak CLI tool, built using the DLL form of JA3Cloak. This project allows you to create both randomized and custom JA3 fingerprints for your TLS connections by leveraging the JA3Cloak DLL.

## Usage

To use the JA3Cloak InteropLoader, you need to specify either the `-r` flag for a randomized JA3 spoofed connection or the `-c` flag for a custom JA3 spoofed connection. Additionally, you can specify the server name, cipher suites, curves, and signature algorithms for custom connections.

### Flags

- `-r`: Create a randomized JA3 spoofed connection
- `-c`: Create a custom JA3 spoofed connection
- `-s`: Specify the server name (default: example.com)
- `-cs`: Comma-separated list of cipher suites (default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA)
- `-curves`: Comma-separated list of supported curves (default: X25519,P256,P384,P521)
- `-sigalgs`: Comma-separated list of supported signature algorithms (default: ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512)

### Examples

#### Randomized JA3 Spoofed Connection

To create a randomized JA3 spoofed connection, use the `-r` flag:

```bash
./JA3Cloak_InteropLoader.exe -r -s example.com
```

#### Custom JA3 Spoofed Connection

To create a custom JA3 spoofed connection, use the `-c` flag:

```bash
./JA3Cloak_InteropLoader.exe -c -s example.com -cs TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA -curves X25519,P256,P384 -sigalgs RSA-PKCS1-SHA256,ECDSA-SHA256
c4-4e15-a7db-ec7ff7acabe3TLS handshake successful
Handshake completed with cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
```