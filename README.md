### GO 对称加密

更易用的对称加密算法库

#### 支持的算法

* SM4 -- 国密
* DES
* DESEDE
* AES

#### 支持的模式

* CBC -- 常用(需要IV)
* ECB -- 常用(不需要IV)
* CFB
* OFB

#### 使用

##### 安装

```shell
go get github.com/topology-zero/crypt@v1.0.3
```

##### 使用

更多用法请查看测试用例

```go
keyByte := []byte("SOME-KEY") // 每种算法的 key 的长度都有特定长度限制
iv := make([]byte, 16)        // 每种算法的 iv 的长度都有特定长度限制, 甚至不需要 iv
copy(iv, keyByte[:16])

newCrypt := NewCrypt(
    []byte(aeskey),
    WithIV(iv),
    WithAlgorithmName(AES), // 使用 aes 算法 
    WithAlgorithmMode(ECB), // 使用 ecb 模式
    WithPKCS7Padding(16),   // 使用 pkcs7 补码
    WithPKCS7UnPadding(),   // 使用 pkcs7 去补码
)

encrypt, err := newCrypt.Encrypt([]byte(inputStr)) // 加密
if err != nil {
    panic(err)
}

toString := base64.StdEncoding.EncodeToString(encrypt)
log.Println(toString)

decrypt, err := newCrypt.Decrypt(encrypt) // 解密
if err != nil {
    panic(err)
}

log.Println(string(decrypt))

if string(decrypt) != inputStr {
    panic("解密失败")
}
```