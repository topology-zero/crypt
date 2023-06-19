package crypt

import (
	"log"
	"testing"
)

const (
	key      = "NEWCAPECNEWCAPEC"
	inputStr = "1234560"
)

func TestCBCCryptSM4(t *testing.T) {
	keyByte := []byte(key)
	iv := make([]byte, 16)
	copy(iv, keyByte[:16])

	newCrypt := NewCrypt(
		[]byte(key),
		WithIV(iv),
		WithAlgorithmName(SM4),
		WithPKCS7Padding(16),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestECBCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(ECB),
		WithPKCS7Padding(16),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestCFBCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithIV([]byte("1234567890123456")),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(CFB),
		WithPKCS7Padding(16),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}
	log.Println(string(decrypt))
	if string(decrypt) != inputStr {
		t.Fatal("解密错误")
	}
}

func TestOFBCryptSM4(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(key),
		WithAlgorithmName(SM4),
		WithAlgorithmMode(OFB),
		WithPKCS7Padding(16),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	log.Printf("%X", encrypt)

	decrypt, err := newCrypt.Decrypt(encrypt)
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
