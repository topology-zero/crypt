package crypt

import (
	"crypto/aes"
	"crypto/cipher"
)

// newAESCipher creates and returns a new cipher.Block.
func newAESCipher(key, iv []byte, mode algorithmMode) (cipher.Block, error) {
	newCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if iv == nil {
		iv = make([]byte, newCipher.BlockSize())
	}
	c := new(SymmetricCipher)
	c.iv = iv
	c.mode = mode
	c.cipher = newCipher
	return c, nil
}
