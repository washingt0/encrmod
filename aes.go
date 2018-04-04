package encrmod

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
	"os"
)

func Pad(src []byte) []byte {
	// AES padding
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func Unpad(src []byte) ([]byte, error) {
	// AES unpadding
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpad error. This could happen when incorrect encryption key is used")
	}

	return src[:(length - unpadding)], nil
}

func GenRandomKey(size int) []byte {
	// Generate an AES key for a specific lenght
	key := make([]byte, size/8)
	_, err := rand.Read(key)
	if err != nil {
		log.Println(err)
	}
	return key
}

func AES256Enc(data []byte, key []byte) ([]byte, error) {
	// Encrypt some []byte with AES-256 algorithm and return ciphertext
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
	// Decrypt some ciphertext encrypted with AES-256 algorithm
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

func AES256Stream(origin, destination string, key []byte) error {
	inFile, err := os.Open(origin)
	if err != nil {
		return err
	}
	defer inFile.Close()
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	// If the key is unique for each ciphertext, then it's ok to use a zero IV.
	var iv [aes.BlockSize]byte
	stream := cipher.NewOFB(block, iv[:])
	outFile, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	if _, err := io.Copy(writer, inFile); err != nil {
		return err
	}
	return nil
}
