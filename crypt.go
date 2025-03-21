package crypt

import (
	"crypto/cipher"
	"errors"
)

type crypt struct {
	key []byte
	iv  []byte

	algorithmName algorithmName
	algorithmMode algorithmMode

	padding   func(src []byte) ([]byte, error)
	unPadding func(src []byte) ([]byte, error)
}

type ICrypt interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type CryptOption func(c *crypt)

// NewCrypt 实例化 crypt 对象
// 注意 key 参数的长度有所限制 (没有在代码中限制)
// 在 SM4 算法下的长度为 16 位 key := make([]byte, 16)
// 在 DES 算法下的长度为 8 位
func NewCrypt(key []byte, opt ...CryptOption) ICrypt {
	target := new(crypt)
	target.key = key

	for _, fn := range opt {
		fn(target)
	}

	if target.padding == nil {
		target.padding = NonePadding
	}

	if target.unPadding == nil {
		target.unPadding = NoneUnPadding
	}
	return target
}

func (c *crypt) Encrypt(data []byte) ([]byte, error) {
	data, err := c.padding(data)
	if err != nil {
		return nil, err
	}
	block, err := c.getCipherBlock(c.algorithmName)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	block.Encrypt(out, data)

	return out, nil
}

func (c *crypt) Decrypt(data []byte) ([]byte, error) {
	block, err := c.getCipherBlock(c.algorithmName)
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(data))
	block.Decrypt(out, data)
	return c.unPadding(out)
}

func (c *crypt) getCipherBlock(name algorithmName) (cipher.Block, error) {
	switch name {
	case SM4:
		return newSM4Cipher(c.key, c.iv, c.algorithmMode)
	case DES:
		return newDESCipher(c.key, c.iv, c.algorithmMode)
	case DESEDE:
		return newDESEDECipher(c.key, c.iv, c.algorithmMode)
	case AES:
		return newAESCipher(c.key, c.iv, c.algorithmMode)
	default:
		return nil, errors.New("not found algorithm name")
	}
}
