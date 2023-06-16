package crypt

import (
	"encoding/base64"
	"log"
	"testing"
)

const (
	aeskey = "NEWCAPECNEWCAPEC"
)

func TestCBCCryptAES(t *testing.T) {
	keyByte := []byte(aeskey)
	iv := make([]byte, 16)
	copy(iv, keyByte[:16])

	newCrypt := NewCrypt(
		[]byte(aeskey),
		WithIV(iv),
		WithAlgorithmName(AES),
		WithPKCS7Padding(16),
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

func TestECBCryptAES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(aeskey),
		WithAlgorithmName(AES),
		WithAlgorithmMode(ECB),
		WithPKCS7Padding(16),
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

func TestCFBCryptAES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(aeskey),
		WithIV([]byte(aeskey)),
		WithAlgorithmName(AES),
		WithAlgorithmMode(CFB),
		WithPKCS7Padding(16),
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

func TestOFBCryptAES(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(aeskey),
		WithIV([]byte(aeskey)),
		WithAlgorithmName(AES),
		WithAlgorithmMode(OFB),
		WithPKCS7Padding(16),
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
