package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	hexKey := "6684a2b04695418d3874e87bcc2711bc573eaa8136f9369fdacfcfbbe53c17c1"
	bytes, _ := hex.DecodeString(hexKey)
	b64 := base64.StdEncoding.EncodeToString(bytes)

	fmt.Printf("HEX: %s\n", hexKey)
	fmt.Printf("B64: %s\n", b64)
	fmt.Println("Copy this B64 value into your config.yaml for 'private_key'")
}
