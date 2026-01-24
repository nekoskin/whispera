package main

import (
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func main() {
	// 1. Config Private Key (Port 3443)
	configPrivKeyB64 := "zU2283YNqtpXNaBS9xHA4OKkXdeYnbR3M0W9hoSGk1I="

	// 2. URL Public Key
	urlPubKeyB64 := "838p12d/tEbCvbGQMCbwH/uaTTtzdShKmATYl2iiIX8="

	// 3. User Hex String
	userHex := "6684a2b04695418d3874e87bcc2711bc573eaa8136f9369fdacfcfbbe53c17c1"

	fmt.Println("--- Analysis ---")

	// Analyze Config Private Key
	privBytes, _ := base64.StdEncoding.DecodeString(configPrivKeyB64)
	fmt.Printf("Config Priv Key (B64): %s\n", configPrivKeyB64)
	fmt.Printf("Config Priv Key (Hex): %x\n", privBytes)

	// Generate Public Key from Config Private Key
	var privKey [32]byte
	copy(privKey[:], privBytes)
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	calcPubKeyB64 := base64.StdEncoding.EncodeToString(pubKey[:])
	fmt.Printf("Calculated Pub Key:    %s\n", calcPubKeyB64)

	// Compare
	if calcPubKeyB64 == urlPubKeyB64 {
		fmt.Println("MATCH: Config Private Key corresponds to URL Public Key.")
	} else {
		fmt.Println("MISMATCH: Config Private Key DOES NOT match URL Public Key.")
		fmt.Printf("Expected (URL): %s\n", urlPubKeyB64)
		fmt.Printf("Actual (Calc):  %s\n", calcPubKeyB64)
	}

	fmt.Println("\n--- User Hex String ---")
	if fmt.Sprintf("%x", privBytes) == userHex {
		fmt.Println("User Hex matches Config Private Key.")
	} else {
		fmt.Println("User Hex does NOT match Config Private Key.")
	}
}
