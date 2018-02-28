package encrmod

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
)

func EncryptFile(path string, key *rsa.PublicKey, priv *rsa.PrivateKey, output string) error {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	filekey := GenRandomKey(256)
	aescipher, err := AES256Enc(file, filekey)
	if err != nil {
		return err
	}
	sum := []byte(fmt.Sprintf("%x", sha256.Sum256(aescipher)))
	rsaplain := append(filekey, sum...)
	rsacipher, err := RSAEncrypt(rsaplain, key)
	fmt.Printf("%x\n", sha256.Sum256(rsacipher))
	if err != nil {
		return err
	}
	rsasign, err := RSASign(priv, rsacipher)
	if err != nil {
		return err
	}
	ioutil.WriteFile(output+".sig", rsasign, 0644)
	outbytes := append(aescipher, rsacipher...)
	ioutil.WriteFile(output, outbytes, 0644)
	return nil
}

func DecryptFile(path string, key *rsa.PrivateKey, pub *rsa.PublicKey, output string) error {
	blob, err := ioutil.ReadFile(path)
	rsacipher := blob[len(blob)-512:]
	aescipher := blob[:len(blob)-512]
	sig, err := ioutil.ReadFile(path + ".sig")
	fmt.Printf("%x\n", sha256.Sum256(rsacipher))
	if err != nil {
		return err
	}
	err = RSAVerify(pub, sig, rsacipher)
	if err != nil {
		return err
	}
	rsaplain, err := RSADecrypt(rsacipher, key)
	if err != nil {
		return err
	}
	filekey := rsaplain[:32]
	sum := string(rsaplain[32:])
	check := fmt.Sprintf("%x", sha256.Sum256(aescipher))
	if sum != check {
		return errors.New("AES ciphertext not valid")
	}
	data, err := AES256Dec(aescipher, filekey)
	if err != nil {
		return err
	}
	ioutil.WriteFile(output, data, 0644)
	return nil
}
