// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh/internal/sntrup761"
)

// sntrup761WithCurve25519sha512 implements the hybrid Streamlined NTRU Prime
// sntrup761 with X25519 key exchange, as implemented by OpenSSH 8.5+ under the
// names sntrup761x25519-sha512 and sntrup761x25519-sha512@openssh.com
// (draft-josefsson-ntruprime-ssh).
type sntrup761WithCurve25519sha512 struct{}

func (kex *sntrup761WithCurve25519sha512) Client(c packetConn, rand io.Reader, magics *handshakeMagics) (*kexResult, error) {
	var c25519kp curve25519KeyPair
	if err := c25519kp.generate(rand); err != nil {
		return nil, err
	}
	pk, sk, err := sntrup761.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	hybridKey := append(pk, c25519kp.pub[:]...)
	if err := c.writePacket(Marshal(&kexECDHInitMsg{hybridKey})); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var reply kexECDHReplyMsg
	if err = Unmarshal(packet, &reply); err != nil {
		return nil, err
	}

	if len(reply.EphemeralPubKey) != sntrup761.CiphertextSize+32 {
		return nil, errors.New("ssh: peer's sntrup761x25519 public value has wrong length")
	}

	kemSecret, err := sntrup761.Decapsulate(sk, reply.EphemeralPubKey[:sntrup761.CiphertextSize])
	if err != nil {
		return nil, err
	}
	c25519Secret, err := curve25519.X25519(c25519kp.priv[:], reply.EphemeralPubKey[sntrup761.CiphertextSize:])
	if err != nil {
		return nil, fmt.Errorf("ssh: peer's sntrup761x25519 public value is not valid: %w", err)
	}
	h := sha512.New()
	h.Write(kemSecret)
	h.Write(c25519Secret)
	secret := h.Sum(nil)

	h.Reset()
	magics.write(h)
	writeString(h, reply.HostKey)
	writeString(h, hybridKey)
	writeString(h, reply.EphemeralPubKey)

	K := make([]byte, stringLength(len(secret)))
	marshalString(K, secret)
	h.Write(K)

	return &kexResult{
		H:         h.Sum(nil),
		K:         K,
		HostKey:   reply.HostKey,
		Signature: reply.Signature,
		Hash:      crypto.SHA512,
	}, nil
}

func (kex *sntrup761WithCurve25519sha512) Server(c packetConn, rand io.Reader, magics *handshakeMagics, priv AlgorithmSigner, algo string) (*kexResult, error) {
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	var kexInit kexECDHInitMsg
	if err = Unmarshal(packet, &kexInit); err != nil {
		return nil, err
	}

	if len(kexInit.ClientPubKey) != sntrup761.PublicKeySize+32 {
		return nil, errors.New("ssh: peer's sntrup761x25519 public value has wrong length")
	}

	ciphertext, kemSecret, err := sntrup761.Encapsulate(rand, kexInit.ClientPubKey[:sntrup761.PublicKeySize])
	if err != nil {
		return nil, err
	}

	var c25519kp curve25519KeyPair
	if err := c25519kp.generate(rand); err != nil {
		return nil, err
	}
	c25519Secret, err := curve25519.X25519(c25519kp.priv[:], kexInit.ClientPubKey[sntrup761.PublicKeySize:])
	if err != nil {
		return nil, fmt.Errorf("ssh: peer's sntrup761x25519 public value is not valid: %w", err)
	}
	hybridKey := append(ciphertext, c25519kp.pub[:]...)

	h := sha512.New()
	h.Write(kemSecret)
	h.Write(c25519Secret)
	secret := h.Sum(nil)

	hostKeyBytes := priv.PublicKey().Marshal()

	h.Reset()
	magics.write(h)
	writeString(h, hostKeyBytes)
	writeString(h, kexInit.ClientPubKey)
	writeString(h, hybridKey)

	K := make([]byte, stringLength(len(secret)))
	marshalString(K, secret)
	h.Write(K)

	H := h.Sum(nil)

	sig, err := signAndMarshal(priv, rand, H, algo)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: hybridKey,
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}
	if err := c.writePacket(Marshal(&reply)); err != nil {
		return nil, err
	}
	return &kexResult{
		H:         H,
		K:         K,
		HostKey:   hostKeyBytes,
		Signature: sig,
		Hash:      crypto.SHA512,
	}, nil
}
