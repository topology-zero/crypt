package crypt

import "crypto/cipher"

type SymmetricCipher struct {
	key    []uint32
	iv     []byte
	cipher cipher.Block
	mode   algorithmMode
}

func (c *SymmetricCipher) BlockSize() int {
	return c.cipher.BlockSize()
}

func (c *SymmetricCipher) Encrypt(dst, src []byte) {
	switch c.mode {
	case CBC:
		c.CBCEncrypt(dst, src)
	case ECB:
		c.ECBEncrypt(dst, src)
	case CFB:
		c.CFBEncrypt(dst, src)
	case OFB:
		c.OFBEncrypt(dst, src)
	default:
		c.ECBEncrypt(dst, src)
	}
}

func (c *SymmetricCipher) Decrypt(dst, src []byte) {
	switch c.mode {
	case CBC:
		c.CBCDecrypt(dst, src)
	case ECB:
		c.ECBDecrypt(dst, src)
	case CFB:
		c.CFBDecrypt(dst, src)
	case OFB:
		c.OFBDecrypt(dst, src)
	default:
		c.ECBDecrypt(dst, src)
	}
}

func (c *SymmetricCipher) CBCEncrypt(dst, src []byte) {
	blockMode := cipher.NewCBCEncrypter(c.cipher, c.iv)
	blockMode.CryptBlocks(dst, src)
}

func (c *SymmetricCipher) CBCDecrypt(dst, src []byte) {
	blockMode := cipher.NewCBCDecrypter(c.cipher, c.iv)
	blockMode.CryptBlocks(dst, src)
}

func (c *SymmetricCipher) ECBEncrypt(dst, src []byte) {
	for len(src) > 0 {
		c.cipher.Encrypt(dst, src[:c.BlockSize()])
		src = src[c.BlockSize():]
		dst = dst[c.BlockSize():]
	}
}

func (c *SymmetricCipher) ECBDecrypt(dst, src []byte) {
	for len(src) > 0 {
		c.cipher.Decrypt(dst, src[:c.BlockSize()])
		src = src[c.BlockSize():]
		dst = dst[c.BlockSize():]
	}
}

func (c *SymmetricCipher) CFBEncrypt(dst, src []byte) {
	blockMode := cipher.NewCFBDecrypter(c.cipher, c.iv)
	blockMode.XORKeyStream(dst, src)
}

func (c *SymmetricCipher) CFBDecrypt(dst, src []byte) {
	blockMode := cipher.NewCFBDecrypter(c.cipher, c.iv)
	blockMode.XORKeyStream(dst, src)
}

func (c *SymmetricCipher) OFBEncrypt(dst, src []byte) {
	blockMode := cipher.NewOFB(c.cipher, c.iv)
	blockMode.XORKeyStream(dst, src)
}

func (c *SymmetricCipher) OFBDecrypt(dst, src []byte) {
	blockMode := cipher.NewOFB(c.cipher, c.iv)
	blockMode.XORKeyStream(dst, src)
}
