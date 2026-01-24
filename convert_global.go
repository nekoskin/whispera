package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func main() {
	hexVal := "0c728faebc9f9b327da53d7eb0b04f608d779b98958aad76f1fa3fe9bcc68eed"
	bytes, err := hex.DecodeString(hexVal)
	if err != nil {
		panic(err)
	}
	b64Val := base64.StdEncoding.EncodeToString(bytes)
	fmt.Print(b64Val)
}
