package main

import (
	"fmt"
	"crypt"
	"strings"
)

func main() {
	str := crypt.ProfileEncode([]byte("foobb@bar.com"))[:32] 
	ad := crypt.PadPKCS7([]byte("admin"), 16)

	tmp := []byte(strings.Repeat("A", 10))
	ad = crypt.ProfileEncode(append(tmp, ad...))[16:32]

	out := append(str,ad...)
	new := crypt.ProfileDecode(out)
	
	for i, c := range new {
		fmt.Printf("%s = %s\n", i, string(c))
	} 
}