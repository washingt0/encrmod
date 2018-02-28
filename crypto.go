package encrmod

import (
	"crypto/rsa"
	"io/ioutil"
)

func EncryptFile(path string, key *rsa.PublicKey, output string) error {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	filekey := GenRandomKey(256)
	aescipher, err := AES256Enc(file, filekey)
	if err != nil {
		return err
	}
	rsacipher, err := RSAEncrypt(filekey, key)
	if err != nil {
		return err
	}
	outbytes := append(aescipher, rsacipher...)
	ioutil.WriteFile(output, outbytes, 0644)
	return nil
}

func DecryptFile(path string, key *rsa.PrivateKey, output string) error {
	blob, err := ioutil.ReadFile(path)
	rsacipher := blob[len(blob)-512:]
	aescipher := blob[:len(blob)-512]
	filekey, err := RSADecrypt(rsacipher, key)
	if err != nil {
		return err
	}
	data, err := AES256Dec(aescipher, filekey)
	if err != nil {
		return err
	}
	ioutil.WriteFile(output, data, 0644)
	return nil
}
