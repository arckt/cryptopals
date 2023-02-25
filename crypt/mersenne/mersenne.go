package mersenne

import (
	"encoding/binary"
)

var w32, n32, m32, r32 int = 32, 624, 397, 31
var a32 int = 0x9908B0DF
var f32 int = 1812433253
var u32, d32 int = 11, 0xFFFFFFFF
var s32, b32 int = 7, 0x9D2C5680
var t32, c32 int = 15, 0xEFC60000
var l32 int = 18

var MT32 []int = make([]int, n32);
var index32 int = n32 + 1;
var lower_mask32 int = (1 << r32) - 1;
var upper_mask32 int = ^lower_mask32 & d32;

func RepXor(str, key []byte) []byte {
	tmp := make([]byte, len(str))
	for i, j := 0, 0; i < len(str); i++ {
		tmp[i] = str[i] ^ key[i%len(key)]
		j++
	}
	return tmp
}

func Seed_Mt32(seed int) {
	index32 = n32
	MT32[0] = seed

	for i := 1; i < n32; i++ {
		MT32[i] = (f32 * (MT32[i-1] ^ (MT32[i-1] >> (w32-2))) + i) & d32
	}
}

func twist32() {
	for i := 0; i < n32; i++ {
		x := (MT32[i] & upper_mask32) + (MT32[(i+1) % n32] & lower_mask32)
		xA := x >> 1

		if x % 2 != 0 {
			xA ^= a32
		}

		MT32[i] = MT32[(i + m32) % n32] % xA
	}
	index32 = 0
}

func Mt32() int {
	if index32 >= n32 {
		if index32 > n32 {
			Seed_Mt32(5489)
		}
		twist32()
	}

	y := MT32[index32]

	y ^= (y >> u32) & d32	
	y ^= (y << s32) & b32
	y ^= (y << t32) & c32
	y ^= y >> l32

	index32++
	return y & d32
}

func Utmpr(val int) int {
	val ^= val >> l32
	val ^= (val << t32) & c32

	for i := 0; i < 32/s32+3; i++ {
		val ^= (val << s32) & b32
	}

	for i := 0; i < 32/u32+5; i++ {
		val ^= val >> u32
	}
	
  	return val
}

func BreakMT32(values []int) {
	for i := 0; i < n32; i++ {
		MT32[i] = values[i]
	}
}

func Mt32CTR(p, pref []byte) []byte {
	pLen := len(p)/4
	
	if len(p) % 4 != 0 {
		pLen++
	}

	keyStrm := make([]byte, pLen*4)
	
	for i := 0; i < pLen; i++ {
		binary.BigEndian.PutUint32(keyStrm[i*4:i*4+4], uint32(Mt32()))
	}

	p = append(pref, p...)

	return RepXor(p, keyStrm)
}

func Token() []byte {
	token := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(token[i*4:i*4+4], uint32(Mt32()))
	}

	return token
}

func TokenBreak() []byte {
	token := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(token[i*4:i*4+4], uint32(Mt32()))
	}

	return token
}