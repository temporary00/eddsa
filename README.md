eddsa
=====

`crypto/rsa` and `crypto/ecdsa` provide `PublicKey` and `PrivateKey` structures
which can be used to unambiguously represent RSA and ECDSA keys.

There is [an implementation of Ed448](https://github.com/otrv4/ed448) for Go,
but it provides basic functions which take pointers to fixed-length arrays. It
is undesirable for code which does type-switches on `interface{}` values to
have to assume that a value of type `*[56]byte` is an Ed448 public key and a
value of type `*[56]byte` is an Ed448 private key.

This package wraps [otrv4/ed448](https://github.com/otrv4/ed448) with a saner
interface much more like `crypto/rsa`, `crypto/ecdsa` and `crypto/elliptic`,
while still allowing you to get the public and private keys as pointers to
fixed-length arrays if you need to.

It is designed to allow other curves to be implemented in future, such as Curve448.
In this regard, the design of this package closely follows `crypto/elliptic`.

Build
-------
```
git clone https://github.com/core-coin/eddsa.git
go build eddsa.go ed448.go
```

Licence
-------
    © 2015 Hugo Landau <hlandau@devever.net>  MIT License

