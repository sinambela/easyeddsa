package easyeddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/sinambela/easybuffer/bytesbuff"
)

var errPubKeyLengthNotValid = errors.New("public key length not valid")

var errPrivKeyLengthNotValid = errors.New("private key length not valid")

var errBufferPoolIsNil = errors.New("buffer pool is null")

var errPubKeyPEMNotValid = errors.New("public key pem data not valid")

var errPrivKeyPEMNotValid = errors.New("private key pem data not valid")

//GetEasyEDDSA for creating EDDSA object
func GetEasyEDDSA(buffPool *bytesbuff.EasyBytes) (data *EasyEDDSA, err error) {
	data = new(EasyEDDSA)

	if err = data.init(buffPool); err != nil {
		return
	}

	return
}

//EasyEDDSA for
type EasyEDDSA struct {
	privKey    ed25519.PrivateKey
	pubKey     ed25519.PublicKey
	bufferPool *bytesbuff.EasyBytes
}

func (x *EasyEDDSA) init(buffPool *bytesbuff.EasyBytes) (err error) {
	(*x).pubKey, (*x).privKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	(*x).bufferPool = buffPool

	return
}

//Sign for signing data
func (x *EasyEDDSA) Sign(data []byte) []byte {
	return ed25519.Sign((*x).privKey, data)
}

//Verify for verifying data
func (x *EasyEDDSA) Verify(data, sig []byte) (bool, error) {
	if len((*x).pubKey) != ed25519.PublicKeySize {
		return false, errPubKeyLengthNotValid
	}

	return ed25519.Verify((*x).pubKey, data, sig), nil
}

//KeyTostring for converting public and private key to string
func (x *EasyEDDSA) KeyTostring() (string, string, error) {
	if (*x).bufferPool == nil {
		return "", "", errBufferPoolIsNil
	}

	//===========process pub key==================================
	pubKBytes, err := x509.MarshalPKIXPublicKey((*x).pubKey)
	if err != nil {
		return "", "", err
	}

	pubKPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKBytes,
	})

	buff := (*x).bufferPool.GetBytesBuffer()

	if _, err := buff.Write(pubKPEM); err != nil {
		(*x).bufferPool.PutBytesBuffer(buff)
		return "", "", err
	}

	pubKStr := buff.String()

	buff.Reset()

	//============process pub key============================================
	privKBytes, err := x509.MarshalPKCS8PrivateKey((*x).privKey)
	if err != nil {
		(*x).bufferPool.PutBytesBuffer(buff)
		return "", "", err
	}

	privKPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKBytes,
	})

	if _, err := buff.Write(privKPEM); err != nil {
		(*x).bufferPool.PutBytesBuffer(buff)
		return "", "", err
	}

	privKStr := buff.String()

	(*x).bufferPool.PutBytesBuffer(buff)

	return pubKStr, privKStr, nil
}

//StringToKeyObject for converting public and private key string to EasyEDDSA
func StringToKeyObject(pubKStr, privKStr string, buffPool *bytesbuff.EasyBytes) (*EasyEDDSA, error) {
	eddsax := new(EasyEDDSA)
	buff := buffPool.GetBytesBuffer()

	//==========process public key string
	if _, err := buff.WriteString(pubKStr); err != nil {
		buffPool.PutBytesBuffer(buff)
		return nil, err
	}

	pubKPEM, _ := pem.Decode(buff.Bytes())
	if pubKPEM == nil {
		buffPool.PutBytesBuffer(buff)
		return nil, errPrivKeyPEMNotValid
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKPEM.Bytes)
	if err != nil {
		buffPool.PutBytesBuffer(buff)
		return nil, err
	}

	eddsax.pubKey = pubKey.(ed25519.PublicKey)

	//===============process private key=======================
	buff.Reset()

	if _, err := buff.WriteString(privKStr); err != nil {
		buffPool.PutBytesBuffer(buff)
		return nil, err
	}

	privKPEM, _ := pem.Decode(buff.Bytes())
	if privKPEM == nil {
		buffPool.PutBytesBuffer(buff)
		return nil, errPrivKeyPEMNotValid
	}

	privK, err := x509.ParsePKCS8PrivateKey(privKPEM.Bytes)
	if err != nil {
		buffPool.PutBytesBuffer(buff)
		return nil, err
	}

	eddsax.privKey = privK.(ed25519.PrivateKey)
	//----------------------------------------------------------------

	buffPool.PutBytesBuffer(buff)

	if len(eddsax.pubKey) != ed25519.PublicKeySize {
		return nil, errPubKeyLengthNotValid
	}

	if len(eddsax.privKey) != ed25519.PrivateKeySize {
		return nil, errPrivKeyLengthNotValid
	}

	eddsax.bufferPool = buffPool

	return eddsax, nil
}

//PubKStringToObj for converting publickey string to object
func PubKStringToObj(pubKStr string, buffPool *bytesbuff.EasyBytes) (ed25519.PublicKey, error) {
	buff := (*buffPool).GetBytesBuffer()

	if _, err := buff.WriteString(pubKStr); err != nil {
		buffPool.PutBytesBuffer(buff)
		return nil, err
	}

	pubKPEM, _ := pem.Decode(buff.Bytes())
	if pubKPEM == nil {
		buffPool.PutBytesBuffer(buff)
		return nil, errPubKeyPEMNotValid
	}

	buffPool.PutBytesBuffer(buff)

	pubK, err := x509.ParsePKIXPublicKey(pubKPEM.Bytes)
	if err != nil {
		return nil, err
	}

	//change to switch=============
	switch pubK := pubK.(type) {
	case *ed25519.PublicKey:
		if len(*pubK) != ed25519.PublicKeySize {
			return *pubK, errPubKeyLengthNotValid
		}

		return *pubK, nil

	default:
		return ed25519.PublicKey{}, errPubKeyLengthNotValid
	}

}
