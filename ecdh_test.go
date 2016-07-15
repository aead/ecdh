// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

// An example for the ECDH key-exchange using the curve P256.
func ExampleGenericKeyExchange() {
	p256 := GenericCurve(elliptic.P256())

	privateAlice, publicAlice, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Alice's private/public key pair: %s\n", err)
	}
	privateBob, publicBob, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Bob's private/public key pair: %s\n", err)
	}

	if err := p256.Check(publicBob); err != nil {
		fmt.Printf("Bob's public key is not on the curve: %s\n", err)
	}
	secretAlice := p256.ComputeSecret(privateAlice, publicBob)

	if err := p256.Check(publicAlice); err != nil {
		fmt.Printf("Alice's public key is not on the curve: %s\n", err)
	}
	secretBob := p256.ComputeSecret(privateBob, publicAlice)

	if !bytes.Equal(secretAlice, secretBob) {
		fmt.Printf("key exchange failed - secret X coordinates not equal\n")
	}

	fmt.Println("\nkey exchange succeed\n")
	// Output:
	// key exchange succeed
}

// An example for the ECDH key-exchange using Curve25519.
func ExampleCurve25519KeyExchange() {
	c25519 := Curve25519()

	privateAlice, publicAlice, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Alice's private/public key pair: %s\n", err)
	}
	privateBob, publicBob, err := c25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate Bob's private/public key pair: %s\n", err)
	}

	if err := c25519.Check(publicBob); err != nil {
		fmt.Printf("Bob's public key is not on the curve: %s\n", err)
	}
	secretAlice := c25519.ComputeSecret(privateAlice, publicBob)

	if err := c25519.Check(publicAlice); err != nil {
		fmt.Printf("Alice's public key is not on the curve: %s\n", err)
	}
	secretBob := c25519.ComputeSecret(privateBob, publicAlice)

	if !bytes.Equal(secretAlice, secretBob) {
		fmt.Printf("key exchange failed - secret X coordinates not equal\n")
	}

	fmt.Println("\nkey exchange succeed\n")
	// Output:
	// key exchange succeed
}

func BenchmarkCurve25519(b *testing.B) {
	curve := Curve25519()
	privateAlice, _, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	for i := 0; i < b.N; i++ {
		curve.ComputeSecret(privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateCurve25519(b *testing.B) {
	curve := Curve25519()
	for i := 0; i < b.N; i++ {
		_, _, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}

func BenchmarkP256(b *testing.B) {
	p256 := GenericCurve(elliptic.P256())
	privateAlice, _, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256.ComputeSecret(privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateP256(b *testing.B) {
	p256 := GenericCurve(elliptic.P256())
	for i := 0; i < b.N; i++ {
		_, _, err := p256.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}

func BenchmarkP521(b *testing.B) {
	p521 := GenericCurve(elliptic.P256())
	privateAlice, _, err := p521.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := p521.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p521.ComputeSecret(privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateP521(b *testing.B) {
	p521 := GenericCurve(elliptic.P256())
	for i := 0; i < b.N; i++ {
		_, _, err := p521.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}
