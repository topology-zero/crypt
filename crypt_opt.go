package crypt

import (
	"bytes"
	"errors"
)

// WithIV 偏移, 注意 ECB/OFB 模式不需要IV
func WithIV(iv []byte) CryptOption {
	return func(c *crypt) {
		c.iv = iv
	}
}

// WithAlgorithmName 使用的加密算法, 支持 SM4/AES/RSA/DSA
func WithAlgorithmName(name algorithmName) CryptOption {
	return func(c *crypt) {
		c.algorithmName = name
	}
}

// WithAlgorithmMode 使用算法模式, 支持 CBC
func WithAlgorithmMode(mode algorithmMode) CryptOption {
	return func(c *crypt) {
		c.algorithmMode = mode
	}
}

// WithPKCS7Padding 使用 pkcs7 填充, 注意: pkcs5 和 pkcs7 算法是一致的
// PKCS#5只是对于8字节（BlockSize=8）进行填充，填充内容为0x01-0x08
// PKCS#7不仅仅是对8字节填充，其BlockSize范围是1-255字节
func WithPKCS7Padding(blockSize int) CryptOption {
	return func(c *crypt) {
		c.padding = func(src []byte) ([]byte, error) {
			padding := blockSize - len(src)%blockSize
			padText := bytes.Repeat([]byte{byte(padding)}, padding)
			return append(src, padText...), nil
		}
	}
}

// WithPKCS7UnPadding 取消填充
func WithPKCS7UnPadding() CryptOption {
	return func(c *crypt) {
		c.unPadding = func(src []byte) ([]byte, error) {
			length := len(src)
			unPadding := int(src[length-1])
			if length-unPadding < 0 {
				return nil, errors.New("invalid un padding")
			}
			return src[:(length - unPadding)], nil
		}
	}
}

// WithZeroPadding 使用 0 填充
func WithZeroPadding(blockSize int) CryptOption {
	return func(c *crypt) {
		c.padding = func(src []byte) ([]byte, error) {
			padding := blockSize - len(src)%blockSize
			padText := bytes.Repeat([]byte{0}, padding)
			return append(src, padText...), nil
		}
	}
}

// WithZeroUnPadding 使用 0 取消填充
func WithZeroUnPadding() CryptOption {
	return func(c *crypt) {
		c.unPadding = func(src []byte) ([]byte, error) {
			length, index := len(src), 0
			for i := length - 1; i >= 0; i-- {
				if src[i] != 0 {
					index = i
					break
				}
			}
			return src[:index+1], nil
		}
	}
}

// WithPadding 使用自定义 padding 算法
func WithPadding(fn func(src []byte) ([]byte, error)) CryptOption {
	return func(c *crypt) {
		c.padding = fn
	}
}

// WithUnPadding 使用自定义 unPadding 算法
func WithUnPadding(fn func(src []byte) ([]byte, error)) CryptOption {
	return func(c *crypt) {
		c.unPadding = fn
	}
}

// NonePadding 不填充
func NonePadding(src []byte) ([]byte, error) {
	return src, nil
}

// NoneUnPadding 不取消填充
func NoneUnPadding(src []byte) ([]byte, error) {
	return src, nil
}
