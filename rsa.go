package encrmod

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func NewKeyPair(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func SaveKeys(priv *rsa.PrivateKey) bool {
	PubASN1 := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	PrivASN1 := x509.MarshalPKCS1PrivateKey(priv)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	})
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: PrivASN1,
	})
	ioutil.WriteFile("key.pub", pubBytes, 0644)
	ioutil.WriteFile("key.priv", privBytes, 0644)
	return true
}

func LoadPrivKey(path string) (*rsa.PrivateKey, error) {
	privBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic(err)
	}
	block, _ := pem.Decode(privBytes)
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panic(err)
	}
	return priv, nil
}

func LoadPubKey(path string) (*rsa.PublicKey, error) {
	pubBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic(err)
	}
	block, _ := pem.Decode(pubBytes)
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Panic(err)
	}
	return pub, nil
}

func RSAEncrypt(data []byte, key *rsa.PublicKey) ([]byte, error) {
	label := []byte("XXX")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, label)
	if err != nil {
		return []byte{}, err
	}
	return ciphertext, nil
}

func RSADecrypt(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	label := []byte("XXX")
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}
