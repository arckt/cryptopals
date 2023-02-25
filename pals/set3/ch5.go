package main

import(
	"fmt"
	"crypt/mersenne"
)

func main() {
	mersenne.Seed_mt32(3)
	fmt.Println(mersenne.Mt32())
	fmt.Println(mersenne.Mt32())
	fmt.Println(mersenne.Mt32())
}