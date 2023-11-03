package main

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strconv"
)

func rotateL(number uint32, bits int) uint32 {
	for i := 0; i < bits; i++ {
		number = (number >> 31) + (number << 1)
	}
	return number
}
func rotateR(number uint32, bits int) uint32 {
	for i := 0; i < bits; i++ {
		number = ((number & 1) << 31) + (number >> 1)
	}
	return number
}

type HashM struct {
	byteArray       []byte
	byteArrayLength int
	sha1HashSum     [5]uint32
	sha1ConstInit   [5]uint32
	sha1ConstK      [4]uint32
	sha1ConstF      [4]func(a, b, c uint32) uint32
}

func (hash *HashM) SHA1() {
	byteArray := hash.byteArray
	byteArray = append(byteArray, 1<<7)
	byteArrayLength := len(byteArray)

	if byteArrayLength%64 < 56 {
		for i := 0; i < 56-byteArrayLength%64; i++ {
			byteArray = append(byteArray, 0)
		}
	} else if byteArrayLength%64 > 56 {
		for i := 0; i < 64-byteArrayLength%64+56; i++ {
			byteArray = append(byteArray, 0)
		}
	}

	byteArray = binary.BigEndian.AppendUint64(byteArray, uint64((byteArrayLength-1)*8))
	byteArrayLength = len(byteArray)

	var wordArray []uint32
	for i := 0; i < byteArrayLength/4; i++ {
		wordArray = append(wordArray, uint32(byteArray[i*4])<<24+uint32(byteArray[i*4+1])<<16+uint32(byteArray[i*4+2])<<8+uint32(byteArray[i*4+3]))
	}

	hash.sha1HashSum = hash.sha1ConstInit
	var bloc [16]uint32
	for i := 0; i < len(wordArray)/16; i++ {
		for j := 0; j < 16; j++ {
			bloc[j] = wordArray[i*16+j]
		}

		hash.sha1Round(bloc)

	}
}

func NewHash(byteArray []byte) HashM {
	return HashM{
		byteArray:       byteArray,
		byteArrayLength: len(byteArray),
		sha1ConstInit:   [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0},
		sha1ConstK:      [4]uint32{0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6},
		sha1ConstF: [4]func(a, b, c uint32) uint32{
			func(a, b, c uint32) uint32 { return (a & b) | (^a & c) },
			func(a, b, c uint32) uint32 { return a ^ b ^ c },
			func(a, b, c uint32) uint32 { return (a & b) | (a & c) | (b & c) },
			func(a, b, c uint32) uint32 { return a ^ b ^ c },
		},
	}
}

func (hash *HashM) sha1Round(bloc [16]uint32) {
	var W [80]uint32

	a := hash.sha1HashSum[0]
	b := hash.sha1HashSum[1]
	c := hash.sha1HashSum[2]
	d := hash.sha1HashSum[3]
	e := hash.sha1HashSum[4]

	for i := 0; i < 80; i++ {
		if i < 16 {
			W[i] = bloc[i]
		} else {
			W[i] = rotateL(W[i-3]^W[i-8]^W[i-14]^W[i-16], 1)
		}
	}

	for i := 0; i < 80; i++ {
		var f, k uint32
		if i < 20 {
			f = hash.sha1ConstF[0](b, c, d)
			k = hash.sha1ConstK[0]
		} else if i < 40 {
			f = hash.sha1ConstF[1](b, c, d)
			k = hash.sha1ConstK[1]
		} else if i < 60 {
			f = hash.sha1ConstF[2](b, c, d)
			k = hash.sha1ConstK[2]
		} else {
			f = hash.sha1ConstF[3](b, c, d)
			k = hash.sha1ConstK[3]
		}

		temp := rotateL(a, 5) + f + e + k + W[i]
		e = d
		d = c
		c = rotateL(b, 30)
		b = a
		a = temp
	}

	hash.sha1HashSum[0] += a
	hash.sha1HashSum[1] += b
	hash.sha1HashSum[2] += c
	hash.sha1HashSum[3] += d
	hash.sha1HashSum[4] += e
}

func (hash *HashM) SetBytes(byteArray []byte) {
	hash.byteArray = byteArray
}

func (hash HashM) GetHex() string {
	var hashHex string
	for i := 0; i < 5; i++ {
		hexPart := strconv.FormatUint(uint64(hash.sha1HashSum[i]), 16)
		hexPartLength := len(hexPart)
		if hexPartLength < 8 {
			for i := 0; i < 8-hexPartLength; i++ {
				hexPart = "0" + hexPart
			}
		}
		hashHex += hexPart
	}
	return hashHex
}

func main() {
	a := NewHash([]byte("on. Pianoforte p"))
	a.SHA1()
	fmt.Println(a.GetHex())
	b := sha1.Sum([]byte("on. Pianoforte p"))
	fmt.Printf("%x", b)
	//var b [16]uint32
	//b[0] = 1 << 31
	//fmt.Println(a.sha1Round(b, a.sha1ConstInit))
}
