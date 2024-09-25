package main

import (
	"C"
	"fmt"
	"net"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// Define the CipherSuiteMap
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

//export CreateRandomizedJA3SpoofedConnection
func CreateRandomizedJA3SpoofedConnection(serverName *C.char) {
	goServerName := C.GoString(serverName)

	// Dial the TCP connection
	rawConn, err := net.Dial("tcp", goServerName+":443")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer rawConn.Close()

	// Create a tls connection with a randomized Client Hello
	config := &tls.Config{ServerName: goServerName, InsecureSkipVerify: true}
	uconn := tls.UClient(rawConn, config, tls.HelloRandomized) // Use HelloRandomized for a randomized fingerprint

	// Perform the TLS handshake
	err = uconn.Handshake()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Verify the connection state
	state := uconn.ConnectionState()
	fmt.Printf("Handshake completed with cipher suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
}

//export CreateCustomJA3SpoofedConnection
func CreateCustomJA3SpoofedConnection(serverName, cipherSuites, curves, signatureAlgorithms *C.char) {
	goServerName := C.GoString(serverName)
	goCipherSuites := C.GoString(cipherSuites)
	goCurves := C.GoString(curves)
	goSignatureAlgorithms := C.GoString(signatureAlgorithms)

	// Dial the TCP connection
	rawConn, err := net.Dial("tcp", goServerName+":443")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer rawConn.Close()

	// Parse cipher suites
	var parsedCipherSuites []uint16
	for _, cs := range splitAndTrim(goCipherSuites) {
		if val, ok := CipherSuiteMap[cs]; ok {
			parsedCipherSuites = append(parsedCipherSuites, val)
		} else {
			fmt.Printf("Warning: Unable to map cipher suite: %s\n", cs)
		}
	}

	// Parse curves
	var parsedCurves []tls.CurveID
	for _, curve := range splitAndTrim(goCurves) {
		if val, ok := CurveIDMap[curve]; ok {
			parsedCurves = append(parsedCurves, val)
		} else {
			fmt.Printf("Warning: Unable to map curve: %s\n", curve)
		}
	}

	// Parse signature algorithms
	var parsedSignatureAlgorithms []tls.SignatureScheme
	for _, sigalg := range splitAndTrim(goSignatureAlgorithms) {
		if val, ok := SignatureSchemeMap[sigalg]; ok {
			parsedSignatureAlgorithms = append(parsedSignatureAlgorithms, val)
		} else {
			fmt.Printf("Warning: Unable to map signature algorithm: %s\n", sigalg)
		}
	}

	// Create a tls connection with a custom Client Hello
	config := &tls.Config{ServerName: goServerName, InsecureSkipVerify: true}
	uconn := tls.UClient(rawConn, config, tls.HelloCustom)

	// Apply custom Client Hello specs
	err = uconn.ApplyPreset(&tls.ClientHelloSpec{
		CipherSuites: parsedCipherSuites,
		Extensions: []tls.TLSExtension{
			&tls.SNIExtension{ServerName: goServerName},
			&tls.SupportedCurvesExtension{Curves: parsedCurves},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: parsedSignatureAlgorithms},
		},
	})
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Perform the TLS handshake
	err = uconn.Handshake()
	if err != nil {
		fmt.Println("TLS handshake failed:", err)
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

func main() {}
