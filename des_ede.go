package crypt

import (
	"crypto/cipher"
	"crypto/des"
)

// NewDESEDECipher creates and returns a new cipher.Block.
func NewDESEDECipher(key, iv []byte, mode algorithmMode) (cipher.Block, error) {
	newCipher, err := des.NewTripleDESCipher(key)
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
