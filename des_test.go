package crypt

import (
	"encoding/base64"
	"log"
	"testing"
)

const (
	deskey = "NEWCAPEC"
)

func TestCBCCryptDES(t *testing.T) {
	keyByte := []byte(deskey)
	iv := make([]byte, 8)
	copy(iv, keyByte[:8])

	newCrypt := NewCrypt(
		[]byte(deskey),
		WithIV(iv),
		WithAlgorithmName(DES),
		WithPKCS7Padding(8),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	toString := base64.StdEncoding.EncodeToString(encrypt)
	log.Println(toString)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(string(decrypt))

	if string(decrypt) != inputStr {
		t.Fatal("解密失败")
	}

}

func TestECBCryptDES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(deskey),
		WithAlgorithmName(DES),
		WithAlgorithmMode(ECB),
		WithPKCS7Padding(8),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	toString := base64.StdEncoding.EncodeToString(encrypt)
	log.Println(toString)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(string(decrypt))

	if string(decrypt) != inputStr {
		t.Fatal("解密失败")
	}
}

func TestCFBCryptDES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(deskey),
		WithIV([]byte{0x0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
		WithAlgorithmName(DES),
		WithAlgorithmMode(CFB),
		WithPKCS7Padding(8),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	toString := base64.StdEncoding.EncodeToString(encrypt)
	log.Println(toString)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(string(decrypt))

	if string(decrypt) != inputStr {
		t.Fatal("解密失败")
	}
}

func TestOFBCryptDES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(deskey),
		WithAlgorithmName(DES),
		WithAlgorithmMode(OFB),
		WithPKCS7Padding(8),
		WithPKCS7UnPadding(),
	)

	encrypt, err := newCrypt.Encrypt([]byte(inputStr))
	if err != nil {
		t.Fatal(err)
	}

	toString := base64.StdEncoding.EncodeToString(encrypt)
	log.Println(toString)

	decrypt, err := newCrypt.Decrypt(encrypt)
	if err != nil {
		t.Fatal(err)
	}

	log.Println(string(decrypt))

	if string(decrypt) != inputStr {
		t.Fatal("解密失败")
	}
}
