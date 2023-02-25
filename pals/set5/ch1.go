package main

import(
	"fmt"
	"math/big"
	"crypt"
	"encoding/binary"
)

func main() {
	p := new(big.Int)
	p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := new(big.Int)
	g.SetString("2",10)
	a := big.NewInt(int64(binary.LittleEndian.Uint64(crypt.RndStr(8))))
	b := big.NewInt(int64(binary.LittleEndian.Uint64(crypt.RndStr(8))))
	A := new(big.Int)
	B := new(big.Int)
	A.Exp(g, a, p)
	B.Exp(g, b, p)
	s1 := new(big.Int)
	s2 := new(big.Int)
	s1.Exp(p, a, p)
	s2.Exp(p, b, p)
	fmt.Println(s1)
}
