package main

import(
	"crypt"
	"fmt"
)

func main() {
	str := "YELLOW SUBMARINE"

	fmt.Println(crypt.PadPKCS7([]byte(str), 20))
}