package main

import(
	"fmt"
	"crypt"
	"crypt/mersenne"
	"time"
)

func main() {
	val := int(time.Now().Unix())
	mersenne.Seed_Mt32(val)
	rnd := time.Duration(crypt.RndStr(1)[0])
	time.Sleep(time.Second * rnd)
	must := mersenne.Mt32()

	curr := int(time.Now().Unix())

	for curr > 0 {
		mersenne.Seed_Mt32(curr)
		match := mersenne.Mt32()
		if  match == must {
			fmt.Println("MATCH FOUND")
			fmt.Println(curr)
			
			break
		}
		curr--
	}
}