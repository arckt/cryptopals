package main

import (
	"fmt"
	"encoding/hex"
)

func main() {
	enc := "1c0111001f010100061a024b53535009181c"
	enc2 := "686974207468652062756c6c277320657965"

	bs, _ := hex.DecodeString(enc)
	bs2, _ := hex.DecodeString(enc2)
	b := make([]byte, len(bs))

	for i := 0; i < len(bs); i++ {
		b[i] = bs[i] ^ bs2[i]
	}

	fmt.Println(hex.EncodeToString(b))
	return
}
