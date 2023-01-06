[![Godoc Reference](https://godoc.org/github.com/aead/ecdh?status.svg)](https://godoc.org/github.com/aead/ecdh)
[![Build Status](https://travis-ci.org/aead/ecdh.svg?branch=master)](https://travis-ci.org/aead/ecdh)

***The ideas of this package have been implemented in the [Go's standard library](https://github.com/golang/go/tree/master/src/crypto/ecdh)
(Go 1.20). It is recommened to use the standard library `crypto/ecdh` package.*** 

## The ECDH key exchange

Elliptic curve Diffie–Hellman (ECDH) is an anonymous key agreement protocol that allows two parties, 
each having an elliptic curve public–private key pair, to establish a shared secret over an insecure channel.  

This package implements a generic interface for ECDH and supports the generic [crypto/elliptic](https://godoc.org/crypto/elliptic)
and the [x/crypto/curve25519](https://godoc.org/golang.org/x/crypto/curve25519) out of the box.

### Installation
Install in your GOPATH: `go get -u github.com/aead/ecdh`  
