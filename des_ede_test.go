package crypt

import (
	"encoding/base64"
	"log"
	"testing"
)

const (
	desedekey = "NEWCAPECNEWCAPECNEWCAPEC"
)

func TestCBCCryptDESEDE(t *testing.T) {
	keyByte := []byte(desedekey)
	iv := make([]byte, 8)
	copy(iv, keyByte[:8])

	newCrypt := NewCrypt(
		[]byte(desedekey),
		WithIV(iv),
		WithAlgorithmName(DESEDE),
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

func TestECBCryptDESEDE(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(desedekey),
		WithAlgorithmName(DESEDE),
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

func TestCFBCryptDESEDE(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(desedekey),
		WithIV([]byte{0x0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}),
		WithAlgorithmName(DESEDE),
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

func TestOFBCryptDESEDE(t *testing.T) {
	newCrypt := NewCrypt(
		[]byte(desedekey),
		WithAlgorithmName(DESEDE),
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
