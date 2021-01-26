package eddsa

import (
	"crypto"
	"io"
	"reflect"
	"unsafe"

	"github.com/core-coin/circl/sign/ed448"
)

const (
	ed448_pubkey_size    = 57
	ed448_privkey_size   = 114
	ed448_signature_size = 114
)

type ed448Impl struct{}

// Ed448 signature scheme.
//
//   Public key size:   57 bytes
//   Private key size:  114 bytes
//   Signature size:    114 bytes
//   Security level:    ~128 bits
//   Preferred prehash: SHA512
//
func Ed448() Curve {
	return ed448Impl{}
}

func (ed448Impl) GenerateKey(rand io.Reader) (priv *PrivateKey, err error) {
	pubbuf, privbuf, err := ed448.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	priv = &PrivateKey{
		PublicKey: PublicKey{
			Curve: Ed448(),
			X:     make([]byte, ed448_pubkey_size),
		},
		D: make([]byte, ed448_privkey_size),
	}
	copy(priv.X, pubbuf[:])
	copy(priv.D, privbuf[:])

	return
}

func (ed448Impl) UnmarshalPub(buffer []byte) (pub *PublicKey, err error) {
	if len(buffer) != ed448_pubkey_size {
		return nil, errInvalidPublicKey
	}
	pub = &PublicKey{
		Curve: Ed448(),
		X:     make([]byte, ed448_pubkey_size),
	}

	copy(pub.X, buffer)

	return
}

func (ed448Impl) UnmarshalPriv(buffer []byte) (priv *PrivateKey, err error) {
	if len(buffer) != ed448_privkey_size {
		return nil, errInvalidPrivateKey
	}
	priv = &PrivateKey{
		PublicKey: PublicKey{
			Curve: Ed448(),
			X:     make([]byte, ed448_pubkey_size),
		},
		D: make([]byte, ed448_privkey_size),
	}

	copy(priv.X, buffer[ed448_pubkey_size:ed448_privkey_size])
	copy(priv.D, buffer[:])

	return
}

func (ed448Impl) Sign(priv *PrivateKey, data []byte) ([]byte, error) {
	if len(priv.D) != ed448_privkey_size {
		return nil, errInvalidPrivateKey
	}

	sig := ed448.Sign(priv.D, data, "")

	signature := make([]byte, ed448_signature_size+ed448_pubkey_size)
	copy(signature, sig[:])
	copy(signature[ed448_signature_size:], priv.X[:])

	return signature[:], nil
}

func (ed448Impl) Verify(pub *PublicKey, data, sig []byte) bool {
	if len(sig) != ed448_signature_size+ed448_pubkey_size || len(pub.X) != ed448_pubkey_size {
		return false
	}

	return ed448.Verify(pub.X, data, sig[:ed448_signature_size], "")
}

func (ed448Impl) Name() string {
	return "Ed448"
}

func (ed448Impl) KeySize() (publicKeySize, privateKeySize, signatureSize int) {
	return ed448_pubkey_size, ed448_privkey_size, ed448_signature_size
}

func (ed448Impl) PreferredPrehash() (crypto.Hash, string) {
	return crypto.SHA256, "SHA256"
}

func (ed448Impl) SigToPub(sig []byte) ([]byte, error) {
	if len(sig) != ed448_signature_size+ed448_pubkey_size {
		return nil, errInvalidSignature
	}

	return sig[ed448_signature_size:], nil
}

func PublicKeyBuffer(pub *PublicKey) *[ed448_pubkey_size]byte {
	if _, ok := pub.Curve.(ed448Impl); !ok {
		return nil
	}

	return cast_pubkey(pub.X)
}

func PrivateKeyBuffer(priv *PrivateKey) *[ed448_privkey_size]byte {
	if _, ok := priv.Curve.(ed448Impl); !ok {
		return nil
	}

	return cast_privkey(priv.D)
}

func cast_pubkey(s []byte) *[ed448_pubkey_size]byte {
	if len(s) < ed448_pubkey_size {
		panic(" called with wrong byte slice")
	}

	return (*[ed448_pubkey_size]byte)(unsafe.Pointer(reflect.ValueOf(s).Pointer()))
}

func cast_privkey(s []byte) *[ed448_privkey_size]byte {
	if len(s) < ed448_privkey_size {
		panic("un144 called with wrong byte slice")
	}

	return (*[ed448_privkey_size]byte)(unsafe.Pointer(reflect.ValueOf(s).Pointer()))
}

func cast_signature(s []byte) *[ed448_signature_size]byte {
	if len(s) < ed448_signature_size {
		panic("un112 called with wrong byte slice")
	}

	return (*[ed448_signature_size]byte)(unsafe.Pointer(reflect.ValueOf(s).Pointer()))
}
