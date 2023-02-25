package main

import(
	"fmt"
	"crypt"
)

func main() {
	tmp := []byte{1,2,3,4,5}
	fmt.Println(crypt.Rrot(tmp, 2))
}