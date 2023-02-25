package main

import(
	"fmt"
	"crypt"
)

func main () {
	fmt.Println(string(crypt.UPadPKCS7(crypt.FakeOracle4Break(),16)))
}