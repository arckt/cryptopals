package main

import(
	"fmt"
	"crypt"
)

func main() {
	tmp1 := crypt.SHA1([]byte("ablacksun"))
	tmp2 := crypt.SHA1([]byte("ablack"))
	fmt.Println(tmp1)
	fmt.Println(crypt.SHA1H(tmp2,[]byte("sun"),6, 1))	
}