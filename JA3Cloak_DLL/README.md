# JA3Cloak DLL

JA3Cloak DLL is a dynamic link library version of the JA3Cloak tool. It provides functions for creating JA3 spoofed connections, allowing you to create both randomized and custom JA3 fingerprints for your TLS connections. This DLL can be used in various programming environments that support calling functions from DLLs.

## Exported Functions

### CreateRandomizedJA3SpoofedConnection

This function creates a randomized JA3 spoofed connection.

### CreateCustomJA3SpoofedConnection

This function creates a custom JA3 spoofed connection.

**Signature:**

```c
void CreateRandomizedJA3SpoofedConnection(const char* serverName);
void CreateCustomJA3SpoofedConnection(const char* serverName, const char* cipherSuites, const char* curves, const char* signatureAlgorithms);
```

**Parameters:**

- `serverName`: The server name to connect to.
- `cipherSuites`: A comma-separated list of cipher suites to use.
- `curves`: A comma-separated list of curves to use.
- `signatureAlgorithms`: A comma-separated list of signature algorithms to use.
