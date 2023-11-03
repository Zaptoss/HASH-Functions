package main

import (
	"crypto/sha1"
	"fmt"
	"os"
	"testing"
)

var myHash = NewHash([]byte{})

func f(b []byte) {
	myHash.SetBytes(b)
	myHash.SHA1()
	//sha1.Sum(b)
}

func TestSHA1String16(t *testing.T) {
	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 16)
	var byteCount int
	var err error
	var offset int

	for {
		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		myHash.SetBytes(buffer[:byteCount])
		myHash.SHA1()
		if myHash.GetHex() != fmt.Sprintf("%x", sha1.Sum(buffer[:byteCount])) {
			t.Errorf("Offset: %d, String: %s", offset, string(buffer))
		}
		offset += byteCount
	}
}

func TestSHA1String32(t *testing.T) {
	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 32)
	var byteCount int
	var err error
	var offset int

	for {
		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		myHash.SetBytes(buffer[:byteCount])
		myHash.SHA1()
		if myHash.GetHex() != fmt.Sprintf("%x", sha1.Sum(buffer[:byteCount])) {
			t.Errorf("Offset: %d, String: %s", offset, string(buffer))
		}
		offset += byteCount
	}
}

func TestSHA1String64(t *testing.T) {
	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 64)
	var byteCount int
	var err error
	var offset int

	for {
		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		myHash.SetBytes(buffer[:byteCount])
		myHash.SHA1()
		if myHash.GetHex() != fmt.Sprintf("%x", sha1.Sum(buffer[:byteCount])) {
			t.Errorf("Offset: %d, String: %s", offset, string(buffer))
		}
		offset += byteCount
	}
}

func TestSHA1String128(t *testing.T) {
	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 128)
	var byteCount int
	var err error
	var offset int

	for {
		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		myHash.SetBytes(buffer[:byteCount])
		myHash.SHA1()
		if myHash.GetHex() != fmt.Sprintf("%x", sha1.Sum(buffer[:byteCount])) {
			t.Errorf("Offset: %d, String: %s", offset, string(buffer))
		}
		offset += byteCount
	}
}

func TestSHA1String255(t *testing.T) {
	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 255)
	var byteCount int
	var err error
	var offset int

	for {
		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		myHash.SetBytes(buffer[:byteCount])
		myHash.SHA1()
		if myHash.GetHex() != fmt.Sprintf("%x", sha1.Sum(buffer[:byteCount])) {
			t.Errorf("Offset: %d, String: %s", offset, string(buffer))
		}
		offset += byteCount
	}
}

func BenchmarkSHA1String16(b *testing.B) {

	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 16)
	var byteCount int
	var err error
	for {

		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		f(buffer[:byteCount])
	}
}

func BenchmarkSHA1String32(b *testing.B) {

	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 32)
	var byteCount int
	var err error
	for {

		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		f(buffer[:byteCount])
	}
}

func BenchmarkSHA1String64(b *testing.B) {

	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 64)
	var byteCount int
	var err error
	for {

		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		f(buffer[:byteCount])
	}
}

func BenchmarkSHA1String128(b *testing.B) {

	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 128)
	var byteCount int
	var err error
	for {

		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		f(buffer[:byteCount])
	}
}

func BenchmarkSHA1String255(b *testing.B) {

	file, _ := os.Open("test_data.txt")
	defer file.Close()

	var buffer = make([]byte, 255)
	var byteCount int
	var err error
	for {

		byteCount, err = file.Read(buffer)
		if err != nil {
			break
		}
		f(buffer[:byteCount])
	}
}
