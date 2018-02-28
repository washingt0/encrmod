package encrmod

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
)

func Pad(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func GenRandomKey(size int) []byte {
	key := make([]byte, size/8)
	_, err := rand.Read(key)
	if err != nil {
		log.Println(err)
	}
	return key
}

func AES256Enc(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if len(data)%aes.BlockSize != 0 {
		data = Pad(data)
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return []byte{}, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func AES256Dec(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}
	if len(data) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	if len(data)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	data, err = Unpad(data)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}
