# JA3Cloak

## Overview

JA3Cloak is a project designed to create spoofed JA3 fingerprints for TLS connections. JA3 fingerprints are used to identify clients based on the specifics of their SSL/TLS handshake. By spoofing these fingerprints, JA3Cloak can help in testing, security research, and evading fingerprint-based detection mechanisms.

## Components

The project consists of several components:

1. **JA3Cloak_InteropLoader**: A C# application that interacts with the JA3Cloak DLL to create spoofed JA3 connections.
2. **JA3Cloak_DLL**: A Go-based DLL that provides the core functionality for creating spoofed JA3 connections.
3. **JA3Cloak_CLI**: A Go-based command-line interface for creating spoofed JA3 connections.

## JA3Cloak_InteropLoader

### Description

The `JA3Cloak_InteropLoader` is a C# application that uses P/Invoke to call functions from the `JA3Cloak.dll`. It provides two main functionalities:
- Creating a randomized JA3 spoofed connection.
- Creating a custom JA3 spoofed connection with specified parameters.

### Usage

To run the `JA3Cloak_InteropLoader`, you need to specify the mode (`-r` for random or `-c` for custom) and optionally provide parameters for the custom mode.

#### Example Commands

- Randomized JA3 Spoofed Connection:
  ```sh
  JA3Cloak_InteropLoader.exe -r
  ```

- Custom JA3 Spoofed Connection
  - Curve Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  - Curve IDs: X25519,P256
  - Signature Algorithm: ECDSAWithP256AndSHA256
    
  ```sh
  JA3Cloak_InteropLoader.exe -c -s example.com -cs TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -curves X25519,P256 -sigalgs ECDSAWithP256AndSHA256
  ```
  
- Custom JA3 Spoofed Connection
  - Curve Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA
  - Curve IDs: X25519,P256,P384
  - Signature Algorithm: SA-PKCS1-SHA256,ECDSA-SHA256
  ```sh
  JA3Cloak_InteropLoader.exe -c -s example.com -cs TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA -curves X25519,P256,P384 -sigalgs RSA-PKCS1-SHA256,ECDSA-SHA256
  ```

### Code Reference

The main logic for handling command-line arguments and invoking the DLL functions is in the `Program.cs` file

## JA3Cloak_DLL

### Description

The `JA3Cloak_DLL` is a Go-based DLL that provides the core functionality for creating spoofed JA3 connections. It exports two main functions:
- `CreateRandomizedJA3SpoofedConnection`: Creates a randomized JA3 spoofed connection.
- `CreateCustomJA3SpoofedConnection`: Creates a custom JA3 spoofed connection with specified parameters.

### Code Reference

The implementation of these functions can be found in the `JA3Cloak_DLL.go` file.

## JA3Cloak_CLI

### Description

The `JA3Cloak_CLI` is a Go-based command-line interface that provides similar functionality to the `JA3Cloak_InteropLoader` but can be run directly from the command line without needing the C# interop layer.

### Usage

To run the `JA3Cloak_CLI`, you need to specify the mode (`-r` for random or `-c` for custom) and optionally provide parameters for the custom mode.

#### Example Commands

- Randomized JA3 Spoofed Connection:
  ```sh
  go run JA3Cloak_CLI.go -r
  ```

- Custom JA3 Spoofed Connection:
  ```sh
  go run JA3Cloak_CLI.go -c -s example.com -cs TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -curves X25519,P256 -sigalgs ECDSAWithP256AndSHA256
  ```

### Code Reference

The main logic for handling command-line arguments and creating spoofed JA3 connections is in the `JA3Cloak_CLI.go` file.

## Potential Uses

1. **Security Research**: Researchers can use JA3Cloak to test the robustness of JA3 fingerprinting mechanisms and explore ways to evade detection.
2. **Penetration Testing**: Penetration testers can use JA3Cloak to simulate different clients and test the security of servers against various JA3 fingerprints.
3. **Privacy**: Users concerned about privacy can use JA3Cloak to mask their true JA3 fingerprint and avoid tracking based on SSL/TLS handshakes.
4. **Development and Testing**: Developers can use JA3Cloak to test their applications against different JA3 fingerprints and ensure compatibility with various clients.

## Building the Project

### Prerequisites

- .NET SDK 7.0
- Go 1.21.5

### Building JA3Cloak_InteropLoader

1. Navigate to the `JA3Cloak_InteropLoader` directory.
2. Run the following command to build the project:
   ```sh
   dotnet build
   ```

### Building JA3Cloak_DLL

1. Navigate to the `JA3Cloak_DLL` directory.
2. Run the following command to build the DLL:
   ```sh
   go build -o JA3Cloak.dll -buildmode=c-shared
   ```

### Running JA3Cloak_CLI

1. Navigate to the `JA3Cloak_CLI` directory.
2. Run the following command to execute the CLI:
   ```sh
   go run JA3Cloak_CLI.go
   ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [uTLS](https://github.com/refraction-networking/utls) for providing the underlying library for TLS fingerprinting.
