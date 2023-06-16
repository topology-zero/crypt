package crypt

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"
)

const (
	key      = "NEWCAPECNEWCAPEC"
	inputStr = "1234560"
	cBCEnStr = "53C27727B1EE94EEAC793502BCD39E88"
	eCBEnStr = "DA36D730FE07C97978C2BDB5E12C8802"
	cFBEnStr = "D8A51BD6E76E6C1D7E8CF029C29B0B5A"
	oFBEnStr = "E1494AFA61EC4CA9762EDF90CB8E0E03"
)

func TestCBCEnCryptSM4(t *testing.T) {
	keyByte := []byte(key)
	iv := make([]byte, 16)
	copy(iv, keyByte[:16])

	newCrypt := NewCrypt(
		[]byte(key),
		WithIV(iv),
		WithAlgorithmName(SM4),
		WithPKCS7Padding(16),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	if fmt.Sprintf("%X", encrypt) != cBCEnStr {
		t.Fatal("加密错误")
	}
}

func TestCBCDeCryptSM4(t *testing.T) {
	keyByte := []byte(key)
	iv := make([]byte, 16)
	copy(iv, keyByte[:16])

	data, _ := hex.DecodeString(cBCEnStr)

	newCrypt := NewCrypt(
		[]byte(key),
		WithIV(iv),
		WithAlgorithmName(SM4),
		WithPKCS7UnPadding(),
	)
	decrypt, err := newCrypt.Decrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestECBEnCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(ECB),
		WithPKCS7Padding(16),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	if fmt.Sprintf("%X", encrypt) != eCBEnStr {
		t.Fatal("加密错误")
	}
}

func TestECBDeCryptSM4(t *testing.T) {
	data, _ := hex.DecodeString(eCBEnStr)
	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(ECB),
		WithPKCS7UnPadding(),
	)
	decrypt, err := newCrypt.Decrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestCFBEnCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithIV([]byte("1234567890123456")),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(CFB),
		WithPKCS7Padding(16),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	if fmt.Sprintf("%X", encrypt) != cFBEnStr {
		t.Fatal("加密错误")
	}
}

func TestCFBDeCryptSM4(t *testing.T) {
	data, _ := hex.DecodeString(cFBEnStr)
	newCrypt := NewCrypt(
		[]byte(key),
		WithIV([]byte("1234567890123456")),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(CFB),
		WithPKCS7UnPadding(),
	)
	decrypt, err := newCrypt.Decrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(decrypt))
	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestOFBEnCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(OFB),
		WithPKCS7Padding(16),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	if fmt.Sprintf("%X", encrypt) != oFBEnStr {
		t.Fatal("加密错误")
	}
}

func TestOFBDeCryptSM4(t *testing.T) {
	data, _ := hex.DecodeString(oFBEnStr)

	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(OFB),
		WithPKCS7UnPadding(),
	)
	decrypt, err := newCrypt.Decrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func X80UnPadding(data []byte) (res []byte) {
	flag := false
	for i := range data {
		if data[i] == 0x80 {
			flag = true
		}

		if flag {
			return
		}

		res = append(res, data[i])
	}
	return
}

func X80Padding(data []byte) (res []byte) {
	dataLen := len(data)
	outPadding := 16 - len(data)%16
	res = make([]byte, dataLen+outPadding)
	copy(res[:dataLen], data)
	res[dataLen] = 0x80
	for i := 1; i < outPadding; i++ {
		res[dataLen+i] = 0
	}
	return res
}
