package main

import(
	"fmt"
	"crypt"
)

func main() {
	fmt.Println(crypt.MD4([]byte("blacksun")))
}
