package main

import(
	"fmt"
	"crypt"
	"encoding/base64"
)

func main() {
	tmp := crypt.Conv("b642.txt")
	
	tmp2, _ := base64.StdEncoding.DecodeString(string(tmp))

	key := crypt.RndStr(16)

	val := crypt.AesCTR(tmp2, key, uint64(0), 16)

	tmp3 := []byte{}

	for i := 0; i < len(val); i++ {
		tmp3 = append(tmp3, byte(7))
	}

	val2 := crypt.EditAesCTR(val, key, tmp3, 0)

	keystr := crypt.RepXor(val2, tmp3)

	if string(crypt.RepXor(val, keystr)) == string(tmp2) {
		fmt.Println("TRUE")
	}
}