package rsaGenerator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

//RsaKey Contains pointers to generated private and public keys.
type RsaKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

//GenerateRSA creates a new private and public key with specified size
func GenerateRSA(size int) *RsaKey {
	rsaPPK, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil
	}
	return &RsaKey{
		PrivateKey: rsaPPK,
		PublicKey:  &rsaPPK.PublicKey,
	}
}

//LoadKey loads rsa key from specified file. It returns nil if fails. SHould be full direct path to each file.
func LoadKey(privatePath, publicPath string) (*RsaKey, error) {
	var rsaKey RsaKey
	pk, err := loadPrivateGobKey(privatePath)

	if err != nil {
		return nil, err
	}
	rsaKey.PrivateKey = pk
	rsaKey.PublicKey = rsaKey.GetPublicKey()
	return &rsaKey, nil
}

//LoadKeySimple use the same name for private and public key. (do not need to add _public or _private)
func LoadKeySimple(name string) (*RsaKey, error) {
	var rsaKey RsaKey
	pk, err := loadPrivateGobKey(name)
	if err != nil {
		return nil, err
	}
	rsaKey.PrivateKey = pk
	if rsaKey.PrivateKey != nil {
		rsaKey.PublicKey = rsaKey.GetPublicKey()
	}
	return &rsaKey, nil
}

//SaveKeys saves keys (_private.key, _private.pem, _public.key, _public.pem)
func (r *RsaKey) SaveKeys(name string) error {
	if err := saveGobKey(fmt.Sprintf("%s_private.key", name), r.PrivateKey); err != nil {
		return err
	}
	if err := savePemKey(fmt.Sprintf("%s_private.pem", name), r.PrivateKey); err != nil {
		return err
	}
	if err := saveGobKey(fmt.Sprintf("%s_public.key", name), r.PublicKey); err != nil {
		return err
	}

	return savePubKey(fmt.Sprintf("%s_public.pem", name), r.PublicKey)

}

//Save saves just the minimum: private key in pem format. Using it you can easily restore all neccesary information.
func (r *RsaKey) Save(name string) {
	savePemKey(name, r.PrivateKey)
}

//GetPrivateKey returns a private key
func (r *RsaKey) GetPrivateKey() *rsa.PrivateKey {
	return r.PrivateKey
}

//GetPublicKey returns a public key
func (r *RsaKey) GetPublicKey() *rsa.PublicKey {
	return &r.PrivateKey.PublicKey
}

func saveGobKey(filename string, key interface{}) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := gob.NewEncoder(file)
	err = enc.Encode(key)
	if err != nil {
		return err
	}
	return nil
}

func loadPrivateGobKey(filename string) (*rsa.PrivateKey, error) {
	key := new(rsa.PrivateKey)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer log.Printf("Closing file %s. %v", file.Name(), file.Close())
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	decPem, _ := pem.Decode(data)
	if decPem == nil {
		return nil, errors.New("Can't decode data")
	}
	key, err = x509.ParsePKCS1PrivateKey(decPem.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func savePemKey(filename string, key *rsa.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	var pkey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	err = pem.Encode(file, pkey)
	if err != nil {
		return err
	}
	return nil
}

func savePubKey(fileName string, pubkey *rsa.PublicKey) error {
	asn1Bytes, err := asn1.Marshal(pubkey)
	if err != nil {
		return err
	}

	var pemkey = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	if err != nil {
		return err
	}
	return nil
}
