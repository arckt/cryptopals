package main

import(
	"fmt"
	"encoding/hex"
	"crypt"
)

func main() {
	s := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	str, _ := hex.DecodeString(s)
	
	fmt.Println(crypt.BruteXor(str))
	return
}
