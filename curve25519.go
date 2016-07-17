// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ecdh

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

type ecdh25519 struct{}

// Curve25519 creates a new ecdh.KeyExchange with
// the elliptic curve Curve25519.
func X25519() KeyExchange {
	return ecdh25519{}
}

func (c ecdh25519) GenerateKey(random io.Reader) (private PrivateKey, public PublicKey, err error) {
	if random == nil {
		random = rand.Reader
	}

	var pri, pub [32]byte
	_, err = io.ReadFull(random, pri[:])
	if err != nil {
		return
	}

	// From https://cr.yp.to/ecdh.html
	pri[0] &= 248
	pri[31] &= 127
	pri[31] |= 64

	curve25519.ScalarBaseMult(&pub, &pri)

	private = pri[:]
	public = pub[:]
	return
}

func (c ecdh25519) PublicKey(private PrivateKey) (public PublicKey) {
	if len(private) != 32 {
		panic("ecdh: private key is not 32 byte")
	}

	var pri, pub [32]byte
	copy(pri[:], private)

	curve25519.ScalarBaseMult(&pub, &pri)

	public = pub[:]
	return
}

func (c ecdh25519) Check(peersPublic PublicKey) (err error) {
	if len(peersPublic) != 32 {
		err = errors.New("peers public key is not 32 byte")
	}
	return
}

func (c ecdh25519) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret []byte) {
	if len(private) != 32 {
		panic("ecdh: private key is not 32 byte")
	}
	if len(peersPublic) != 32 {
		panic("ecdh: peers public key is not 32 byte")
	}

	var sec, pri, pub [32]byte
	copy(pri[:], private)
	copy(pub[:], peersPublic)

	curve25519.ScalarMult(&sec, &pri, &pub)

	secret = sec[:]
	return
}
