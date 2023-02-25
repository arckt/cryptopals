package main

import(
	"fmt"
	"crypt"
	"strings"
)

func main() {
	len0 := len(";admin=true;")
	tmp := []byte(strings.Repeat("A", len0))

	len1 := len("comment1=cooking%20MCs;userdata=")
	tmp2 := crypt.CTREnc(tmp)
	tmp3 := tmp2[len1:len1+len0]
	tmp3 = crypt.RepXor(tmp3, tmp)
	tmp3 = crypt.RepXor(tmp3, []byte(";admin=true;"))
	for i := 0; i < len0; i++ {
		
		tmp2[len1+i] = tmp3[i]
	}

	fmt.Println(crypt.CTRDec(tmp2))
}