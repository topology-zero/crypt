package crypt

type algorithmName int

const (
	DES algorithmName = iota
	DESEDE
	AES

	//RSA
	//DSA

	SM4
)

type algorithmMode int

const (
	CBC algorithmMode = iota
	ECB
	CFB
	OFB
)
