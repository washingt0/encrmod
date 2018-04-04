package encrmod

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func EncryptFile(path string, key *rsa.PublicKey, priv *rsa.PrivateKey, output string) error {
	/*
		Encrypt a file with a unique AES-256 key and encrypt that key RSA,
		next sign RSA encrypted content and append it to end of ciphertext.
		The final file should be:
		[ENCRYPTED_DATA] + [512 BYTES OF RSA ENCRYPTED CONTENT]
	*/
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
	/*
		Validate signed content and encrypted data integrity, after that,
		decrypt AES-256 key from RSA ciphertext and decrypt AES-256 ciphertext
		for plain text.
	*/
	blob, err := ioutil.ReadFile(path)
	rsacipher := blob[len(blob)-512:]
	aescipher := blob[:len(blob)-512]
	sig, err := ioutil.ReadFile(path + ".sig")
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

func EncryptFileS(in_path, out_path string, pub *rsa.PublicKey, priv *rsa.PrivateKey) error {
	aeskey := GenRandomKey(256)
	AES256Stream(in_path, out_path, aeskey)
	rsacipher, err := RSAEncrypt(aeskey, pub)
	if err != nil {
		return err
	}
	inFile, err := os.Open(out_path)
	if err != nil {
		return err
	}
	defer inFile.Close()
	h := sha256.New()
	if _, err := io.Copy(h, inFile); err != nil {
		return err
	}
	checkFile := h.Sum(nil)
	sign, err := RSASign(priv, append(rsacipher, checkFile...))
	if err != nil {
		return err
	}
	ioutil.WriteFile(out_path+".meta", append(rsacipher, sign...), 0644)
	return nil
}

func DecryptFileS(in_file, out_file string, pub *rsa.PublicKey, priv *rsa.PrivateKey) error {
	meta, err := ioutil.ReadFile(in_file + ".meta")
	if err != nil {
		return err
	}
	rsacipher := append([]byte{}, meta[:512]...)
	sign := append([]byte{}, meta[512:]...)
	f, err := os.Open(in_file)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	checkFile := h.Sum(nil)
	if err = RSAVerify(pub, sign, append(rsacipher, checkFile...)); err != nil {
		return err
	}
	key, err := RSADecrypt(rsacipher, priv)
	if err != nil {
		return err
	}
	if err = AES256Stream(in_file, out_file, key); err != nil {
		return err
	}
	return nil
}
