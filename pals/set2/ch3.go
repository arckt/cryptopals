package main

import(
	"crypt"
	"fmt"
)

func main() {
	tmp := crypt.OracECBCEnc([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	fmt.Println(crypt.OracECBCDec(tmp))
}