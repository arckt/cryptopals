package main

import (
	"fmt"
	"crypt"
	"encoding/base64"
)

func main() {
	p := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	n, _ := base64.StdEncoding.DecodeString(p)
	k := "YELLOW SUBMARINE"

	key := crypt.AesCTR([]byte(n),[]byte(k), uint64(0), 16)
	fmt.Println(string(key))
}
