package encrmod

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

func NewKeyPair(bits int) (*rsa.PrivateKey, error) {
	// Generate a new key pair with the specified lenght
	return rsa.GenerateKey(rand.Reader, bits)
}

func SaveKeys(priv *rsa.PrivateKey) bool {
	// Save a key pair on disk
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
	// Load a private key from a file specified by path parameter
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
	// Load a public key from a file specified by path parameter
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
	// Encrypt data with RSA algorithm and SHA-256 as hash
	label := []byte("XXX")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, label)
	if err != nil {
		return []byte{}, err
	}
	return ciphertext, nil
}

func RSADecrypt(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	// Decrypt RSA ciphertext using SHA-256 as hash
	label := []byte("XXX")
	data, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

func RSASign(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Sign some data with RSA private key
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		return []byte{}, err
	}
	return signature, nil
}

func RSAVerify(key *rsa.PublicKey, sig []byte, data []byte) error {
	// Verify RSA signature
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sig)
	return err
}
