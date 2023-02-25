package main

import(
	"fmt"
	"crypt"
	"encoding/base64"
)

func main() {
	tmp := crypt.Conv("b64.txt")
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	tmp2, _ := base64.StdEncoding.DecodeString(string(tmp))

	fmt.Println(string(crypt.DecAesCBC(tmp2, key, iv)))
}