package main

import (
	"fmt"
	"net"
	"strings"

	"flag"
	"os"

	tls "github.com/refraction-networking/utls"
)

var CipherSuiteMap = map[string]uint16{
	"TLS_RSA_WITH_AES_128_CBC_SHA":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"TLS_RSA_WITH_AES_256_CBC_SHA":                  tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_RSA_WITH_AES_256_GCM_SHA384":               tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	// Add other cipher suites as needed
}

// Define the CurveIDMap
var CurveIDMap = map[string]tls.CurveID{
	"X25519":    tls.X25519,
	"P256":      tls.CurveP256,
	"P384":      tls.CurveP384,
	"P521":      tls.CurveP521,
	"secp256r1": tls.CurveSECP256R1,
	"secp384r1": tls.CurveSECP384R1,
	"secp521r1": tls.CurveSECP521R1,
	// Add other curve IDs as needed
}

// Define the SignatureSchemeMap
var SignatureSchemeMap = map[string]tls.SignatureScheme{
	"RSA-PKCS1-SHA256":  tls.PKCS1WithSHA256,
	"RSA-PKCS1-SHA384":  tls.PKCS1WithSHA384,
	"RSA-PKCS1-SHA512":  tls.PKCS1WithSHA512,
	"ECDSA-SHA256":      tls.ECDSAWithP256AndSHA256,
	"ECDSA-SHA384":      tls.ECDSAWithP384AndSHA384,
	"ECDSA-SHA512":      tls.ECDSAWithP521AndSHA512,
	"RSA-SHA256":        tls.PKCS1WithSHA256,
	"RSA-SHA384":        tls.PKCS1WithSHA384,
	"RSA-SHA512":        tls.PKCS1WithSHA512,
	"ECDSA-P256-SHA256": tls.ECDSAWithP256AndSHA256,
	"ECDSA-P384-SHA384": tls.ECDSAWithP384AndSHA384,
	"ECDSA-P521-SHA512": tls.ECDSAWithP521AndSHA512,
	// Add other signature schemes as needed
}

func main() {
	random := flag.Bool("r", false, "Create a randomized JA3 spoofed connection")
	custom := flag.Bool("c", false, "Create a custom JA3 spoofed connection")
	serverName := flag.String("s", "example.com", "Specify the server name")
	cipherSuites := flag.String("cs", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA", "Comma-separated list of cipher suites")
	curves := flag.String("curves", "X25519,P256,P384,P521", "Comma-separated list of supported curves")
	signatureAlgorithms := flag.String("sigalgs", "ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512", "Comma-separated list of supported signature algorithms")
	flag.Parse()

	if *random {
		createRandomizedJA3SpoofedConnection(*serverName)
	} else if *custom {
		createCustomJA3SpoofedConnection(*serverName, *cipherSuites, *curves, *signatureAlgorithms)
	} else {
		fmt.Println("Please specify either -r for random or -c for custom")
		fmt.Println("Instructions for creating a custom JA3 spoofed connection:")
		fmt.Println("  -s: Specify the server name (default: example.com)")
		fmt.Println("  -cs: Comma-separated list of cipher suites (default: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_CBC_SHA)")
		fmt.Println("  -curves: Comma-separated list of supported curves (default: X25519,P256,P384,P521)")
		fmt.Println("  -sigalgs: Comma-separated list of supported signature algorithms (default: ECDSAWithP256AndSHA256,ECDSAWithP384AndSHA384,ECDSAWithP521AndSHA512,RSAWithSHA256,RSAWithSHA384,RSAWithSHA512)")
		os.Exit(1)
	}
}

func createRandomizedJA3SpoofedConnection(serverName string) {
	// Dial the TCP connection
	rawConn, err := net.Dial("tcp", serverName+":443")
	if err != nil {
		panic(err)
	}
	defer rawConn.Close()

	// Create a tls connection with a randomized Client Hello
	config := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
	uconn := tls.UClient(rawConn, config, tls.HelloRandomized) // Use HelloRandomized for a randomized fingerprint

	// Perform the TLS handshake
	err = uconn.Handshake()
	if err != nil {
		panic(err)
	}

	// Verify the connection state
	state := uconn.ConnectionState()
	fmt.Printf("Handshake completed with cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
}

func createCustomJA3SpoofedConnection(serverName, cipherSuites, curves, signatureAlgorithms string) {
	// Dial the TCP connection
	rawConn, err := net.Dial("tcp", serverName+":443")
	if err != nil {
		panic(err)
	}
	defer rawConn.Close()

	// Parse cipher suites
	var parsedCipherSuites []uint16
	for _, cs := range splitAndTrim(cipherSuites) {
		if val, ok := CipherSuiteMap[cs]; ok {
			parsedCipherSuites = append(parsedCipherSuites, val)
		} else {
			fmt.Printf("Warning: Unable to map cipher suite: %s\n", cs)
		}
	}

	// Parse curves
	var parsedCurves []tls.CurveID
	for _, curve := range splitAndTrim(curves) {
		if val, ok := CurveIDMap[curve]; ok {
			parsedCurves = append(parsedCurves, val)
		} else {
			fmt.Printf("Warning: Unable to map curve: %s\n", curve)
		}
	}

	// Parse signature algorithms
	var parsedSignatureAlgorithms []tls.SignatureScheme
	for _, sigalg := range splitAndTrim(signatureAlgorithms) {
		if val, ok := SignatureSchemeMap[sigalg]; ok {
			parsedSignatureAlgorithms = append(parsedSignatureAlgorithms, val)
		} else {
			fmt.Printf("Warning: Unable to map signature algorithm: %s\n", sigalg)
		}
	}

	// Create a tls connection with a custom Client Hello
	config := &tls.Config{ServerName: serverName, InsecureSkipVerify: true}
	uconn := tls.UClient(rawConn, config, tls.HelloCustom)

	// Apply custom Client Hello specs
	err = uconn.ApplyPreset(&tls.ClientHelloSpec{
		CipherSuites: parsedCipherSuites,
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{ServerName: serverName},
			&tls.SupportedCurvesExtension{Curves: parsedCurves},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: parsedSignatureAlgorithms},
		},
	})
	if err != nil {
		panic(err)
	}

	// Perform the TLS handshake
	err = uconn.Handshake()
	if err != nil {
		fmt.Printf("TLS handshake failed: %v\n", err)
		rawConn.Close()
		return
	}
	fmt.Println("TLS handshake successful")

	// Verify the connection state
	state := uconn.ConnectionState()
	fmt.Printf("Handshake completed with cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
}

func splitAndTrim(input string) []string {
	var result []string
	for _, item := range strings.Split(input, ",") {
		result = append(result, strings.TrimSpace(item))
	}
	return result
}
