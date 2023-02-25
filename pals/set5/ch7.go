package main

import(
	"fmt"
	"math/big"
	"crypt"
	"encoding/binary"
	"crypto/sha256"
	"crypto/hmac"
)

func main() {
	N := new(big.Int)
	N.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := new(big.Int)
	g.SetString("2", 10)
	k := new(big.Int)
	k.SetString("3", 10)
	v := new(big.Int)
	a := big.NewInt(int64(binary.LittleEndian.Uint64(crypt.RndStr(8))))
	b := big.NewInt(int64(binary.LittleEndian.Uint64(crypt.RndStr(8))))
	I := "email@email.com"
	P := "thisispassword"
	fmt.Printf("C & S: N: %v g: %v k: %v I: %v P: %v\n",N,g,k,I,P)

	salt := crypt.RndStr(4)
	x1 := sha256.Sum256(append(salt, []byte(P)...))
	x := big.NewInt(int64(binary.LittleEndian.Uint64(x1[:8])))
	v.Exp(g, x, N)
	//A := new(big.Int)
	//A.Exp(g, a, N)
	A := N
	fmt.Printf("C->S: I: %v A: %v\n", I, A)
	B := new(big.Int)
	B.Mul(k, v)
	Tmp := new(big.Int)
	Tmp.Exp(g, b, N)
	B.Add(B, Tmp)
	B.Mod(B, N)
	fmt.Printf("S->C: salt: %v B: %v\n", salt, B)
	u1 := sha256.Sum256(append(A.Bytes(), B.Bytes()...))
	u := big.NewInt(int64(binary.LittleEndian.Uint64(u1[:8])))
	S1 := new(big.Int)
	Tmp2 := new(big.Int)
	Tmp2.Exp(g, x, N)
	Tmp2.Mul(k, Tmp2)
	Tmp2.Sub(B, Tmp2)
	S1.Mul(u, x)
	S1.Add(S1, a)
	S1.Exp(Tmp, S1, N)

	S2 := new(big.Int)
	S2.Exp(v, u, N)
	S2.Mul(A, S2)
	S2.Exp(S2, b, N)
	fmt.Println("S1")
	fmt.Println(S1)
	fmt.Println("S2")
	fmt.Println(S2)
	k01 := sha256.Sum256(S1.Bytes())
	k02 := sha256.Sum256(S2.Bytes())
	mac1 := hmac.New(sha256.New, salt)
	mac2 := hmac.New(sha256.New, salt)
	mac1.Write(k01[:])
	ans1 := mac1.Sum(nil)
	mac2.Write(k02[:])
	ans2 := mac2.Sum(nil)

	fmt.Printf("C->S: %v\n", ans1)
	fmt.Printf("S->C: %v\n", ans2)
}
