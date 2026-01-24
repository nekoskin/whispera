package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

func main() {
	// 1. Config Key (Current)
	configKeyB64 := "zU2283YNqtpXNaBS9xHA4OKkXdeYnbR3M0W9hoSGk1I="

	// 2. URL Pub Key
	urlPubKeyB64 := "838p12d/tEbCvbGQMCbwH/uaTTtzdShKmATYl2iiIX8="

	// 3. User Hex Key
	userKeyHex := "6684a2b04695418d3874e87bcc2711bc573eaa8136f9369fdacfcfbbe53c17c1"

	fmt.Println("=== KEY DIAGNOSTICS ===")

	// --- Check 1: Does Config Key match URL Pub Key? ---
	fmt.Println("\n1. CONFIG KEY aka 'zU2283...'")
	cfgBytes, _ := base64.StdEncoding.DecodeString(configKeyB64)
	fmt.Printf("   Hex: %x\n", cfgBytes)

	var cfgPriv [32]byte
	copy(cfgPriv[:], cfgBytes)
	var cfgPub [32]byte
	curve25519.ScalarBaseMult(&cfgPub, &cfgPriv)
	cfgPubB64 := base64.StdEncoding.EncodeToString(cfgPub[:])

	if cfgPubB64 == urlPubKeyB64 {
		fmt.Printf("   -> Generates URL Pub Key? YES (%s)\n", cfgPubB64)
	} else {
		fmt.Printf("   -> Generates URL Pub Key? NO  (%s)\n", cfgPubB64)
	}

	// --- Check 2: Does User Hex Key match URL Pub Key? ---
	fmt.Println("\n2. USER HEX KEY aka '6684a...'")
	userBytes, err := hex.DecodeString(userKeyHex)
	if err != nil {
		fmt.Printf("   Error decoding hex: %v\n", err)
		return
	}
	// Print B64 of User Key so user can copy it if needed
	userKeyB64 := base64.StdEncoding.EncodeToString(userBytes)
	fmt.Printf("   Base64 Representation: %s\n", userKeyB64)

	var userPriv [32]byte
	copy(userPriv[:], userBytes)
	var userPub [32]byte
	curve25519.ScalarBaseMult(&userPub, &userPriv)
	userPubB64 := base64.StdEncoding.EncodeToString(userPub[:])

	if userPubB64 == urlPubKeyB64 {
		fmt.Printf("   -> Generates URL Pub Key? YES (%s)\n", userPubB64)
	} else {
		fmt.Printf("   -> Generates URL Pub Key? NO  (Generates: %s)\n", userPubB64)
	}
}
