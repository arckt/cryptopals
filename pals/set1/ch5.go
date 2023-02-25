package main

import (
	"fmt"
	"encoding/hex"
	"crypt"
)

func main() {
	stri := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	out := xor.RepXor([]byte(stri),[]byte("ICE"))
	fmt.Println(hex.EncodeToString(out))
	return
}
