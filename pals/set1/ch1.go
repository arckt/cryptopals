package main

import (
	"fmt"
	"encoding/base64"
	"encoding/hex"
)

func main() {
	enc := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	bs, _ := hex.DecodeString(enc)

	encoded := base64.StdEncoding.EncodeToString(bs)

	fmt.Println(string(encoded))
}
