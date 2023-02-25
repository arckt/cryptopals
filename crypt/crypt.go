package crypt

import (
	"os"
	"fmt"
	"sort"
	"bufio"
	"strings"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	
)

type best struct {
	raw   string
	score float64
	key   byte
}

//ispycode
 type ByLen []string

func (a ByLen) Len() int {
   return len(a)
}
 
func (a ByLen) Less(i, j int) bool {
   return len(a[i]) < len(a[j])
}
 
func (a ByLen) Swap(i, j int) {
   a[i], a[j] = a[j], a[i]
}

func StrSrt(s ByLen) {
	sort.Sort(ByLen(s))
}

//Ainar-G
func Reverse(ss []string) {
    last := len(ss) - 1
    for i := 0; i < len(ss)/2; i++ {
        ss[i], ss[last-i] = ss[last-i], ss[i]
    }
}

//FndBlk find a specific block in two dimensional byte array and return higher order idx
func FndBlk(s [][]byte, fnd []byte) int {
	for i, c := range s {
		if string(fnd) == string(c) {
			return i
		}
	}

	return -1
}

//LLrot32 rotates the byte array s to the left n times
func LLrot32(n uint32, b uint32) uint32 {
	return ((n << b) | (n >> (32 - b))) & 0xffffffff
}

//AdjMat returns the first index where the adjacent block matches
func AdjMat(s [][]byte) int {
	for i := 0; i < len(s)-1; i++ {
		if string(s[i]) == string(s[i+1]) {
			return i
		}
	}

	return -1
}

// MakeDict returns array of s with varying bytes 0-255 at index idx
func MakeDict(s []byte, idx, size int) [][]byte {
	res := [][]byte{}

	if len(s) != size - 1 {
		return res
	}

	for i := 0; i < 256; i++ {
		tmp := []byte{}

		for j := 0; j < size; j++ {
			if j != idx {
				tmp = append(tmp, s[j])
			} else {
				tmp = append(tmp, byte(i))
			}
		}

		res = append(res, tmp)
	}
	
	return res
}

// RndStr returns array b which is a random byte array of length size
func RndStr(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)

	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	return b
}

//Conv returns a byte array of all contents in a file
func Conv(file string) []byte {
	file2, err := os.Open(file)
	tmp := []byte{}

	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(file2)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		text := scanner.Text()
		for _, c := range text {
			tmp = append(tmp, byte(c))
		}
	}

	return tmp
}

//PadPKCS7 pads a byte array str to size length
func PadPKCS7(str []byte, length int) []byte {
	res := str
	req := length - len(str)%length

	if len(str)%length > 0 {
		for i := 0; i < req; i++ {
			res = append(res, byte(req))
		}
	}

	return res
}

//UPadPKCS7 removes pad array of byte array str
func UPadPKCS7(str []byte, block int) []byte {
	cnt := str[len(str)-1]
	cnt2 := 0

	if int(cnt) > block {
		return []byte{}
	}

	blocks := (len(str)/block)-1

	init := block - int(cnt)

	pad := str[block*blocks+init:block*blocks+block]

	last := str[16*blocks:(blocks+1)*16]

	for i := block-1; i >= 0; i-- {
		if last[i] ==  cnt {
			cnt2 += 1
		} else {
			break
		}
	}

	for _, c := range pad {
		if c != cnt && c <= byte(block) {
			return []byte{}
		}
	}

	if int(cnt) != cnt2 {
		return []byte{}
	}

	return str[:blocks*block+init]
}

//RepXor does repeating xor on byte array str with key
func RepXor(str, key []byte) []byte {
	tmp := make([]byte, len(str))
	for i, j := 0, 0; i < len(str); i++ {
		tmp[i] = str[i] ^ key[i%len(key)]
		j++
	}
	return tmp
}

//MemSplt turns byte array mem to blocks of size length
func MemSplt(mem []byte, length int) [][]byte {
	tmp := [][]byte{}
	lent := 0
	trig := true

	if len(mem)%length > 0 {
		lent = (len(mem) / length) + 1
	} else {
		lent = (len(mem) / length)
		trig = false
	}

	for i := 0; i < lent; i++ {
		m := []byte{}

		if i == lent-1 && trig {
			for j := 0; j < len(mem)%length; j++ {
				m = append(m, mem[i*length+j])
			}
		} else {
			for j := 0; j < length; j++ {
				m = append(m, mem[i*length+j])
			}
		}

		tmp = append(tmp, m)
	}

	return tmp
}

//Hamm returns the hamming distance between two byte arrays
func Hamm(s1, s2 []byte) float64 {
	res := float64(0)

	for i := 0; i < len(s2); i++ {
		for q := 7; q >= 0; q-- {
			res += float64(((s1[i] ^ s2[i]) >> q) & 1)
		}
	}

	return res
}

//HammRep returns the average hamming distance between two blocks of size length
func HammRep(s1 []byte, length int) float64 {
	res := float64(0)

	tmp := MemSplt(s1, length)

	for i := 0; i < len(tmp)-1; i++ {
		res += Hamm(tmp[i], tmp[i+1])
	}

	return res / float64(len(tmp)-1)
}

//Tpose returns a transposed 2d byte array s
func Tpose(s [][]byte) [][]byte {
	res := [][]byte{}

	for i := 0; i < len(s[0]); i++ {
		m := []byte{}

		for j := 0; j < len(s); j++ {
			if len(s[j])-1 >= i {
				m = append(m, s[j][i])
			}
		}
		res = append(res, m)
	}

	return res
}

//DecAesECB returns a decrypted AES byte array in ECB mode credits to: phss
func DecAesECB(s, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(s))
	size := len(key)

	for bs, be := 0, size; bs < len(s); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], s[bs:be])
	}

	return decrypted
}

//EncAesECB returns an encrypted AES byte array in ECB mode
func EncAesECB(s, key []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	size := len(key)
	encrypted := make([]byte, len(s))

	for bs, be := 0, size; bs < len(s); bs, be = bs+size, be+size {
		cipher.Encrypt(encrypted[bs:be], s[bs:be])
	}

	return encrypted
}

//DecAesCBC returns a decrypted AES byte array in CBC mode
func DecAesCBC(s, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	decrypted := make([]byte, len(s))
	size := len(key)
	res := []byte{}

	for bs, be := 0, size; bs < len(s); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], s[bs:be])
		var tmp []byte
		//fmt.Println(decrypted[bs:be])
		if bs < size {
			tmp = RepXor(decrypted[bs:be], iv[:len(key)])
		} else {
			tmp = RepXor(decrypted[bs:be], s[bs-size:be-size])
		}
		res = append(res, tmp...)
	}
	return res
}

//EncAesCBC returns an encrypted AES byte array in CBC mode
func EncAesCBC(s, key, iv []byte) []byte {
	cipher, _ := aes.NewCipher([]byte(key))
	size := len(key)
	size2 := len(s)
	res := make([]byte, size2)

	for bs, be := 0, size; bs < len(s); bs, be = bs+size, be+size {
		var tmp2 []byte
		if bs < size {
			tmp2 = RepXor(s[bs:be], iv[:len(key)])
		} else {
			tmp2 = RepXor(s[bs:be], res[bs-size:be-size])
		}

		cipher.Encrypt(res[bs:be], tmp2)
	}
	return res
}

func AesCTR(s, k []byte, nonce uint64, blk int) []byte {
	size := blk
	k2 := make([]byte, len(k))
	big := []byte{}
	cipher, _ := aes.NewCipher([]byte(k))
	littlEnK2 := make([]byte, 8)
	binary.LittleEndian.PutUint64(littlEnK2,nonce)

	for i := 0; i < len(s)/size+1; i++ {
			littlEnK1 := make([]byte, blk/2)
			binary.LittleEndian.PutUint64(littlEnK1,uint64(i))

			k3 := append(littlEnK2, littlEnK1...)
			k2 = make([]byte, len(k))
			
			cipher.Encrypt(k2,k3)
			big = append(big, k2...)
	}
	return RepXor(s, big)
}

//BloCnt returns the number of blocks that are the same
func BloCnt(s []byte, length int) int {
	great := 0

	tmp2 := MemSplt(s, length)
	tmp4 := make(map[string]int)

	for _, h := range tmp2 {
		if tmp4[string(h)] == 0 {
			tmp4[string(h)] = 1
		} else {
			tmp4[string(h)]++
		}
	}

	for _, j := range tmp4 {
		if j > great {
			great = j
		}
	}

	return great
}

//OracECBCEnc that pads 5-10 before and after s with random key of 16 bytes
//with 50/50 chance of using ECB or CBC
func OracECBCEnc(s []byte) []byte {
	key := RndStr(16)
	bef := 5 + (RndStr(1)[0] % 6)
	aft := 5 + (RndStr(1)[0] % 6)

	tmp := append(RndStr(int(bef)), s...)
	tmp = append(tmp, RndStr(int(aft))...)

	wh := RndStr(1)[0] % 2

	if wh == 0 {
		return EncAesCBC(tmp, key, RndStr(16))
	}

	return EncAesECB(tmp, key)
}

//OracECBCDec detects if ECB or CBC was used on byte array s
func OracECBCDec(s []byte) string {
	if BloCnt(s, 16) > 1 {
		return "ECB"
	}

	return "CBC"
}

//FakeOracle returns Aes-128-Ecb with constant key
func FakeOracle(s []byte) []byte {
	fakeKey := []byte{82, 247, 121, 50, 216, 252, 157, 12, 11, 79, 129, 207, 25, 46, 30, 108}
	unkn, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	tmp := append(s, unkn...)
	payload := PadPKCS7(tmp, 16) 
	return EncAesECB(payload, fakeKey)
}

//FakeOracleBreak attemps to break string s through calls to FakeOracle
func FakeOracleBreak() []byte {
	yourstr := ""
	length := len(FakeOracle([]byte(yourstr)))
	orig := length
	init := length
	block := 0
	total := 0
	res := []byte{}
	
	for init == length {
		yourstr = yourstr + "A"
		length = len(FakeOracle([]byte(yourstr)))
		total++
	}

	init = length

	for init == length {
		yourstr = yourstr + "A"
		length = len(FakeOracle([]byte(yourstr)))
		block++
	}

	test := strings.Repeat("A", 8)
	test = test + test + test + test

	if BloCnt([]byte(test), 16) > 1 {
		for i := 0; i <= orig-total; i++ {
			offset := block - (i % block) - 1
			init := []byte(strings.Repeat("A", offset))

			plain := append(init, res...)
			plain2 := MemSplt(plain, block)
			tmp := FakeOracle(init)
			tmp2 := MemSplt(tmp, block)

			dict := MakeDict(plain2[i/block], block-1, block)
			
			for j, c := range dict {
				out := FakeOracle(c)
				out = out[0:16]

				if string(tmp2[i/block]) == string(out) {
					res = append(res, byte(j))
					continue
				}
			}
		}
	}

	return res
}

//Kvparse parses byte array of k=v in the form of map[k] = v
func KvParse(s []byte) map[string][]byte {
	res := make(map[string][]byte)
	i, j := 0, 0
	key := []byte{}

	for ;j < len(s); j++ {
		if s[j] == '=' {
			key = s[i:j]
			i = j + 1
		} else if s[j] == '&' {
			res[string(key)] = s[i:j]
			i = j + 1
		} else if j == len(s) - 1 {
			res[string(key)] = s[i:j + 1]
		}
	}

	return res
}

//Profilefor does the opposite of Kvparse
func Profilefor(s []byte) []byte {
	str := string(s)
	res := strings.Replace(str, "&", "", -1)
	res = strings.Replace(res, "=", "", -1)

	return []byte("email=" + string(res) + "&uid=10&role=user") 
}

//FakeOracle2 new fake doesnt append
func FakeOracle2(s []byte) []byte {
	fakeKey := []byte{82, 247, 121, 50, 216, 252, 157, 12, 11, 79, 129, 207, 25, 46, 30, 108}
	payload := PadPKCS7(s, 16) 
	return EncAesECB(payload, fakeKey)
}

//ProfileEncode is ProfileFor(FakeOracle2((arg))
func ProfileEncode(s []byte) []byte {
	res := Profilefor(s)	
	res = FakeOracle2(res)
	return res
}

//ProfileDecode is KvParse(DecAesECB(arg))
func ProfileDecode(s []byte) map[string][]byte {
	fakekey := []byte{82, 247, 121, 50, 216, 252, 157, 12, 11, 79, 129, 207, 25, 46, 30, 108}
	real := DecAesECB(s, fakekey)
	return KvParse(UPadPKCS7(real, 16))
}

//FakeOracle3 is rnd length and rndstr
func FakeOracle3(s []byte) []byte{
	fakeKey := []byte{82, 247, 121, 50, 216, 252, 157, 12, 11, 79, 129, 207, 25, 46, 30, 108}
	pref := []byte{12, 67, 86, 34, 17}
	unkn, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	tmp := append(s, unkn...)
	tmp2 := append(pref, tmp...)
	payload := PadPKCS7(tmp2, 16) 
	return EncAesECB(payload, fakeKey)
}

func OracleBreak3() []byte{
	yourstr := ""
	length := len(FakeOracle3([]byte(yourstr)))
	init := length
	block := 0
	res := []byte{}
	init = length

	test := strings.Repeat("A", 16)
	test = test + test + test + test

	for init == length {
		yourstr += string('A')
		length = len(FakeOracle3([]byte(yourstr)))
	}

	init = length

	for init == length {
		yourstr += string('A')
		length = len(FakeOracle3([]byte(yourstr)))
		block++
	}

	if BloCnt(FakeOracle3([]byte(test)), block) > 1 {
		yourstr = ""

		for AdjMat(MemSplt(FakeOracle3([]byte(yourstr)), block)) < 0 {
			yourstr = yourstr + "A"
			length = len(FakeOracle3([]byte(yourstr)))
		}

		idx := AdjMat(MemSplt(FakeOracle3([]byte(yourstr)), block))
		off := yourstr[:len(yourstr)%block]
		total := len(FakeOracle3([]byte(off))) - (block * idx)

		for i := 0; i < total; i++ {
			offset := block - (i % block) - 1
			in := []byte(string(off) + strings.Repeat("A", offset))

			plain := append([]byte(strings.Repeat("A", offset)), res...)
			plain2 := MemSplt(plain, block)

			tmp := FakeOracle3(in)
			tmp2 := MemSplt(tmp, block)

			dict := MakeDict(plain2[i/block], block-1, block)

			if len(dict) == 0 {
				return res
			}
			
			for j, c := range dict {
				out := FakeOracle3([]byte(string(off) + string(c)))
				out = out[idx*16:idx*16+16]
				
				if string(tmp2[i/block+idx]) == string(out) {
					res = append(res, byte(j))
					continue
				}
			}
		}
	}
	
	return res
}

//CBCEnc tests CBC attacks
func CBCEnc(str []byte) []byte {
	s := string(str)
	tmp := strings.Replace(s, ";", "", -1 )
	tmp = strings.Replace(tmp, "=", "", -1 )
	
	tmp = "comment1=cooking%20MCs;userdata=" + tmp + ";comment2=%20like%20a%20pound%20of%20bacon"

	iv := []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
	key := iv
	tmp2 := PadPKCS7([]byte(tmp), 16)
	return EncAesCBC([]byte(tmp2), key, iv)
}

//CBCDec confirms CBC attacks
func CBCDec(str []byte) bool {
	iv := []byte{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5}
	key := iv
	tmp := string(DecAesCBC(str, key, iv))
	return strings.Contains(tmp, ";admin=true;")
}

func BlkMch(first, second [][]byte) int {
	iter := len(first)

	if len(second) < iter {
		iter = len(second)
	}

	for i := 0; i < iter; i++ {
		if string(first[i]) != string(second[i]) {
			return i
		}
	}

	return -1
}

func OffMch(first, second [][]byte, i int) bool {
	if string(first[i]) == string(second[i]) {
		return true
	} else {
		return true
	}
}

func PrefLen(block int) int {
	str := ""
	init := MemSplt(CBCEnc([]byte(str)),16)
	str += "A"
	new := MemSplt(CBCEnc([]byte(str)),16)
	
	idx := BlkMch(new,init)
	total := idx * 16

	idx += 1

	for !(OffMch(new, init, idx)) {
		init = MemSplt(CBCEnc([]byte(str)),16)
		str += "A"
		new = MemSplt(CBCEnc([]byte(str)),16)
		total += 1
	}

	return total
}

func CBCBreak() bool {
	yourstr := "A"
	init := len(CBCEnc([]byte(yourstr)))
	length := init
	block := 0

	for init == length {
		yourstr += string('A')
		length = len(CBCEnc([]byte(yourstr)))
	}

	init = length

	for init == length {
		yourstr += string('A')
		length = len(CBCEnc([]byte(yourstr)))
		block++
	}

	length2 := PrefLen(block)

	payload := strings.Repeat("A", length2 % block)

	payload += strings.Repeat("A", block * 2)

	str := CBCEnc([]byte(payload))
	tmp := str[length2:length2 + block]
	req := ";admin=true;"
	tmp2 := strings.Repeat("A", len(req))
	tmp3 := RepXor([]byte(req), []byte(tmp2))
	tmp4 := RepXor(tmp, tmp3)
	res := string(str[:length2]) + string(tmp4) + string(str[len(tmp4)+length2:])
	
	return CBCDec([]byte(res))
}

func FakeOracle4(idx int, k []byte) []byte {
	str := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	res := []string{}

	for _, c := range str {
		tmp2, _ := base64.StdEncoding.DecodeString(c)
		res = append(res,string(tmp2))
	}
	
	tmp := PadPKCS7([]byte(res[idx]),16)

	return EncAesCBC(tmp, k, k)
}

func FakeOracle42(s, key, iv []byte) string {
	if len(UPadPKCS7(DecAesCBC(s,key,iv),16)) == 0 {
		return "Invalid padding"
	} else {
		return "Valid padding"
	}
}

func FakeOracle4Break() []byte {
	idx := int(RndStr(1)[0]%10)
	key := RndStr(16)
	
	init2 := FakeOracle4(idx, key)
	init := MemSplt(init2,16)

	res := []byte{}

	for i := 1; i < len(init); i++ {
		tmp := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,}
		tmp3 := init[i]
			for j := 15; j >= 0; j-- {
				tmp4 := make([]byte,16)
				copy(tmp4, tmp)
				for r := 0; r < 16; r++ {
					tmp4[r] ^= byte(16-j)				
				}
			
				for h := 0; h < 256; h++ {
					tmp4[j] = byte(h)

					if FakeOracle42([]byte(string(tmp4) + string(tmp3)),key,key) == "Valid padding" {
						tmp[j] = byte(h) ^ byte(16-j)
					}
				}
		}	
		res = append(res, RepXor(tmp,init[i-1])...)
	}

	return res
}

func SHA1(s []byte) []byte {
	h0 := uint32(0x67452301)
    h1 := uint32(0xEFCDAB89)
    h2 := uint32(0x98BADCFE)
    h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)
	
	origByteLen := uint32(len(s))
	origBitLen := origByteLen * 8
	s = append(s, byte(0x80))
	pad := make([]byte, ((56 - (origByteLen + 1) % 64) % 64))
	s = append(s, pad...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp,uint64(origBitLen))
	s = append(s, tmp...)

	for i := 0; i < len(s); i += 64 {
		w := make([]uint32,80)

		for j := 0; j < 16; j++ {
			w[j] = binary.BigEndian.Uint32(s[i + j * 4: i + j * 4 + 4]) 
		}

		for j := 16; j < 80; j++ {
			maj := make([]byte, 4)
			val := w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
			binary.LittleEndian.PutUint32(maj, val)
			tmp2 := LLrot32(val, 1)
			w[j] = tmp2
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		for j := 0; j < 80; j++ {
			f := uint32(0)
			k := uint32(0)
			
			if j >= 0 && j <= 19 {
				f = d ^ (b & (c ^ d))
				k = uint32(0x5A827999)
			} else if j >= 20 && j <= 39 {
				f = b ^ c ^ d
                k = uint32(0x6ED9EBA1)
			} else if j >= 40 && j <= 59 {
				f = (b & c) | (b & d) | (c & d) 
                k = uint32(0x8F1BBCDC)
			} else if j >= 60 && j <= 79 {
				f = b ^ c ^ d
                k = uint32(0xCA62C1D6)
			}

			val0 := a
			val1 := b

			a, b, c, d, e = (LLrot32(val0, 5) + f + e + k + w[j]) & 0xFFFFFFFF, 
                            a, LLrot32(val1, 30), c, d

		}
		
		h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
	}

	res := []byte{}
	res0 := make([]byte, 4)
	binary.BigEndian.PutUint32(res0, h0)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h1)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h2)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h3)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h4)
	res = append(res, res0...)
	
	return res
}

func SHA1Mac(s, k []byte) []byte {
	return SHA1(append(k, s...))
}

func SHA1W(s []byte, h0, h1, h2, h3, h4 uint32, leng int) []byte { 
	origByteLen := leng + len(s)
	fmt.Println(origByteLen)
	origBitLen := origByteLen * 8
	s = append(s, byte(0x80))
	pad := make([]byte, ((56 - (origByteLen + 1) % 64) % 64))
	s = append(s, pad...)
	tmp := make([]byte, 8)
	binary.BigEndian.PutUint64(tmp,uint64(origBitLen))
	s = append(s, tmp...)

	for i := 0; i < len(s); i += 64 {
		w := make([]uint32,80)

		for j := 0; j < 16; j++ {
			w[j] = binary.BigEndian.Uint32(s[i + j * 4: i + j * 4 + 4]) 
		}

		for j := 16; j < 80; j++ {
			maj := make([]byte, 4)
			val := w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
			binary.LittleEndian.PutUint32(maj, val)
			tmp2 := LLrot32(val, 1)
			w[j] = tmp2
		}

		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		for j := 0; j < 80; j++ {
			f := uint32(0)
			k := uint32(0)
			
			if j >= 0 && j <= 19 {
				f = d ^ (b & (c ^ d))
				k = uint32(0x5A827999)
			} else if j >= 20 && j <= 39 {
				f = b ^ c ^ d
                k = uint32(0x6ED9EBA1)
			} else if j >= 40 && j <= 59 {
				f = (b & c) | (b & d) | (c & d) 
                k = uint32(0x8F1BBCDC)
			} else if j >= 60 && j <= 79 {
				f = b ^ c ^ d
                k = uint32(0xCA62C1D6)
			}

			val0 := a
			val1 := b

			a, b, c, d, e = (LLrot32(val0, 5) + f + e + k + w[j]) & 0xFFFFFFFF, 
                            a, LLrot32(val1, 30), c, d

		}
		
		h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff 
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff
	}

	res := []byte{}
	res0 := make([]byte, 4)
	binary.BigEndian.PutUint32(res0, h0)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h1)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h2)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h3)
	res = append(res, res0...)
	binary.BigEndian.PutUint32(res0, h4)
	res = append(res, res0...)
	
	return res
}

func SHA1H(s, p []byte, l2, l int) []byte {
	newlen := ((56 - (l2 + 1) % 64) % 64) + 8 + 1 + l2
	a := binary.BigEndian.Uint32(s[:4])
	b := binary.BigEndian.Uint32(s[4:8])
	c := binary.BigEndian.Uint32(s[8:12])
	d := binary.BigEndian.Uint32(s[12:16])
	e := binary.BigEndian.Uint32(s[16:20])
	
	return SHA1W(p, a, b, c, d, e, newlen)
}

func F(x, y, z uint32) uint32 {
	return ((x & y) | ((^x) & z))
}

func G(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func H(x, y, z uint32) uint32 {
	return x ^ y ^ z
}

func shift(x, s uint32) uint32 {
	return ((x << s) & 0xFFFFFFFF) | (x >> (32 - s))
}

func R1(X []uint32, a, b, c, d, k, s uint32) uint32 {
	return shift((a + F(b,c,d) + X[k]) & 0xffffffff, s)
}

func R2(X []uint32, a, b, c, d, k, s uint32) uint32 {
	return shift((a + G(b,c,d) + X[k] + 0x5a827999) & 0xffffffff, s)
}

func R3(X []uint32, a, b, c, d, k, s uint32) uint32 {
	return shift((a + H(b,c,d) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
}

func MD4(s []byte) []byte {
	A := uint32(0x67452301)
    B := uint32(0xEFCDAB89)
    C := uint32(0x98BADCFE)
    D := uint32(0x10325476)
	
	origByteLen := uint32(len(s))
	origBitLen := origByteLen * 8
	s = append(s, byte(0x80))
	pad := make([]byte, ((56 - (origByteLen + 1) % 64) % 64))
	s = append(s, pad...)
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp,uint64(origBitLen))
	s = append(s, tmp...)

	for i := 0; i < len(s); i += 64 {
		X := make([]uint32,16)

		for j := 0; j < 16; j++ {
			X[j] = binary.LittleEndian.Uint32(s[i + j * 4: i + j * 4 + 4]) 
		}

		AA := A
		BB := B
		CC := C
		DD := D

		A = R1(X,A,B,C,D, 0, 3)
		D = R1(X,D,A,B,C, 1, 7)
		C = R1(X,C,D,A,B, 2, 11)
		B = R1(X,B,C,D,A, 3, 19)

		A = R1(X,A,B,C,D, 4, 3)
		D = R1(X,D,A,B,C, 5, 7)
		C = R1(X,C,D,A,B, 6, 11)
		B = R1(X,B,C,D,A, 7, 19)

		A = R1(X,A,B,C,D, 8, 3)
		D = R1(X,D,A,B,C, 9, 7)
		C = R1(X,C,D,A,B, 10, 11)
		B = R1(X,B,C,D,A, 11, 19)

		A = R1(X,A,B,C,D, 12, 3)
		D = R1(X,D,A,B,C, 13, 7)
		C = R1(X,C,D,A,B, 14, 11)
		B = R1(X,B,C,D,A, 15, 19)

		A = R2(X,A,B,C,D, 0, 3)
		D = R2(X,D,A,B,C, 4, 5)
		C = R2(X,C,D,A,B, 8, 9)
		B = R2(X,B,C,D,A, 12, 13)

		A = R2(X,A,B,C,D, 1, 3)
		D = R2(X,D,A,B,C, 5, 5)
		C = R2(X,C,D,A,B, 9, 9)
		B = R2(X,B,C,D,A, 13, 13)

		A = R2(X,A,B,C,D, 2, 3)
		D = R2(X,D,A,B,C, 6, 5)
		C = R2(X,C,D,A,B, 10, 9)
		B = R2(X,B,C,D,A, 14, 13)

		A = R2(X,A,B,C,D, 3, 3)
		D = R2(X,D,A,B,C, 7, 5)
		C = R2(X,C,D,A,B, 11, 9)
		B = R2(X,B,C,D,A, 15, 13)

		A = R3(X,A,B,C,D, 0, 3)
		D = R3(X,D,A,B,C, 8, 9)
		C = R3(X,C,D,A,B, 4, 11)
		B = R3(X,B,C,D,A, 12, 15)

		A = R3(X,A,B,C,D, 2, 3)
		D = R3(X,D,A,B,C, 10, 9)
		C = R3(X,C,D,A,B, 6, 11)
		B = R3(X,B,C,D,A, 14, 15)

		A = R3(X,A,B,C,D, 1, 3)
		D = R3(X,D,A,B,C, 9, 9)
		C = R3(X,C,D,A,B, 5, 11)
		B = R3(X,B,C,D,A, 13, 15)

		A = R3(X,A,B,C,D, 3, 3)
		D = R3(X,D,A,B,C, 11, 9)
		C = R3(X,C,D,A,B, 7, 11)
		B = R3(X,B,C,D,A, 15, 15)

		A = (A + AA) & 0xFFFFFFFF
		B = (B + BB) & 0xFFFFFFFF
		C = (C + CC) & 0xFFFFFFFF
		D = (D + DD) & 0xFFFFFFFF
	}

	res := []byte{}
	res0 := make([]byte, 4)
	binary.LittleEndian.PutUint32(res0, A)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, B)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, C)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, D)
	res = append(res, res0...)
	
	return res
}

func MD4W(s []byte, A, B, C, D, leng uint32) []byte {
	
	origByteLen := uint32(len(s)) + leng
	origBitLen := origByteLen * 8
	s = append(s, byte(0x80))
	pad := make([]byte, ((56 - (origByteLen + 1) % 64) % 64))
	s = append(s, pad...)
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp,uint64(origBitLen))
	s = append(s, tmp...)

	for i := 0; i < len(s); i += 64 {
		X := make([]uint32,16)

		for j := 0; j < 16; j++ {
			X[j] = binary.LittleEndian.Uint32(s[i + j * 4: i + j * 4 + 4]) 
		}

		AA := A
		BB := B
		CC := C
		DD := D

		A = R1(X,A,B,C,D, 0, 3)
		D = R1(X,D,A,B,C, 1, 7)
		C = R1(X,C,D,A,B, 2, 11)
		B = R1(X,B,C,D,A, 3, 19)

		A = R1(X,A,B,C,D, 4, 3)
		D = R1(X,D,A,B,C, 5, 7)
		C = R1(X,C,D,A,B, 6, 11)
		B = R1(X,B,C,D,A, 7, 19)

		A = R1(X,A,B,C,D, 8, 3)
		D = R1(X,D,A,B,C, 9, 7)
		C = R1(X,C,D,A,B, 10, 11)
		B = R1(X,B,C,D,A, 11, 19)

		A = R1(X,A,B,C,D, 12, 3)
		D = R1(X,D,A,B,C, 13, 7)
		C = R1(X,C,D,A,B, 14, 11)
		B = R1(X,B,C,D,A, 15, 19)

		A = R2(X,A,B,C,D, 0, 3)
		D = R2(X,D,A,B,C, 4, 5)
		C = R2(X,C,D,A,B, 8, 9)
		B = R2(X,B,C,D,A, 12, 13)

		A = R2(X,A,B,C,D, 1, 3)
		D = R2(X,D,A,B,C, 5, 5)
		C = R2(X,C,D,A,B, 9, 9)
		B = R2(X,B,C,D,A, 13, 13)

		A = R2(X,A,B,C,D, 2, 3)
		D = R2(X,D,A,B,C, 6, 5)
		C = R2(X,C,D,A,B, 10, 9)
		B = R2(X,B,C,D,A, 14, 13)

		A = R2(X,A,B,C,D, 3, 3)
		D = R2(X,D,A,B,C, 7, 5)
		C = R2(X,C,D,A,B, 11, 9)
		B = R2(X,B,C,D,A, 15, 13)

		A = R3(X,A,B,C,D, 0, 3)
		D = R3(X,D,A,B,C, 8, 9)
		C = R3(X,C,D,A,B, 4, 11)
		B = R3(X,B,C,D,A, 12, 15)

		A = R3(X,A,B,C,D, 2, 3)
		D = R3(X,D,A,B,C, 10, 9)
		C = R3(X,C,D,A,B, 6, 11)
		B = R3(X,B,C,D,A, 14, 15)

		A = R3(X,A,B,C,D, 1, 3)
		D = R3(X,D,A,B,C, 9, 9)
		C = R3(X,C,D,A,B, 5, 11)
		B = R3(X,B,C,D,A, 13, 15)

		A = R3(X,A,B,C,D, 3, 3)
		D = R3(X,D,A,B,C, 11, 9)
		C = R3(X,C,D,A,B, 7, 11)
		B = R3(X,B,C,D,A, 15, 15)

		A = (A + AA) & 0xFFFFFFFF
		B = (B + BB) & 0xFFFFFFFF
		C = (C + CC) & 0xFFFFFFFF
		D = (D + DD) & 0xFFFFFFFF
	}

	res := []byte{}
	res0 := make([]byte, 4)
	binary.LittleEndian.PutUint32(res0, A)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, B)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, C)
	res = append(res, res0...)
	binary.LittleEndian.PutUint32(res0, D)
	res = append(res, res0...)
	
	return res
}

func MD4H(s, p []byte, l2, l int) []byte {
	newlen := uint32(((56 - (l2 + 1) % 64) % 64) + 8 + 1 + l2)
	a := binary.BigEndian.Uint32(s[:4])
	b := binary.BigEndian.Uint32(s[4:8])
	c := binary.BigEndian.Uint32(s[8:12])
	d := binary.BigEndian.Uint32(s[12:16])
	
	return MD4W(p, a, b, c, d, newlen)
}

func HMACSHA1(k, m []byte) []byte {
	key := k

	if len(k) > 64 {
		key = SHA1(k)
	}

	if len(key) < 64 {
		pad := make([]byte, 64 - len(key))
		key = append(key, pad...)
	}

	o_key := []byte{}
	i_key := []byte{}

	for i := 0; i < 64; i++ {
		o_key = append(o_key, key[i] ^ 0x5c)
		i_key = append(i_key, key[i] ^ 0x36)
	}

	return SHA1(append(o_key, SHA1(append(i_key, m...))...))
}

//engFreq returns english score of a particular byte array
func engFreq(s []byte) float64 {
	str := strings.ToLower(string(s))
	sum := float64(0)

	m := map[rune]float64{
		'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881, 'g': 0.0158610,
		'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124, 'n': 0.0564513,
		'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357, 'u': 0.0225134,
		'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182,
	}

	for _, c := range str {
		sum += m[c]
	}
	return sum
}

//BruteXor brute forces single character xor enc and returns unencrypted data, the score,
//and the key
func BruteXor(enc []byte) (string, float64, byte) {
	be := best{raw: "", score: 0, key: 0}

	for i := 0; i < 255; i++ {
		b := make([]byte, len(enc))
		for j := 0; j < len(enc); j++ {
			b[j] = enc[j] ^ byte(i)
		}

		tmp := engFreq(b)
		if tmp > be.score {
			be.raw = string(b)
			be.score = tmp
			be.key = byte(i)
		}
	}
	return be.raw, be.score, be.key
}

//BruteRepXor breaks multi key xored str with keylengths keyMin-keyMax and returns
//decrypted stirng great
func BruteRepXor(str []byte, keyMin, keyMax int) []byte {
	keys := make(map[int]float64)

	if keyMax > len(str) {
		fmt.Println("error: max int is too big")
		os.Exit(1)
	}

	for i := keyMin; i <= keyMax; i++ {
		keys[i] = HammRep(str, i) / float64(i)
	}

	min := make([]int, 3)
	for h := 0; h < 3; h++ {
		smallest := keyMin
		for i, c := range keys {
			if c < keys[smallest] {
				smallest = i
			}
		}
		keys[smallest] = 1000000
		min[h] = smallest
	}

	res := [][]byte{}
	res2 := [][]byte{}

	for _, c := range min {
		tmp := MemSplt(str, c)
		tmp2 := Tpose(tmp)
		var key []byte

		for j := 0; j < len(tmp2); j++ {
			_, _, part := BruteXor(tmp2[j])
			key = append(key, part)
		}

		res2 = append(res2, key)
		res = append(res, RepXor(str, key))
	}

	great := res[0]

	for _, c := range res {

		if engFreq(c) > engFreq(great) {
			great = c
		}
	}

	return great
}
