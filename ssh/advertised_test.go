// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"slices"
	"testing"
)

type kexCaptureTransport struct {
	packetConn
}

func (n *kexCaptureTransport) prepareKeyChange(*NegotiatedAlgorithms, *kexResult) error { return nil }
func (n *kexCaptureTransport) setStrictMode() error                                     { return nil }
func (n *kexCaptureTransport) setInitialKEXDone()                                       {}

func TestAdvertisedKexInitKeepsStrictKEX(t *testing.T) {
	a, b := memPipe()
	defer a.Close()
	defer b.Close()
	config := &Config{
		AdvertisedKeyExchanges: []string{"sntrup761x25519-sha512@openssh.com", KeyExchangeCurve25519},
		AdvertisedMACs:         []string{"umac-64-etm@openssh.com", HMACSHA256ETM},
		AdvertisedCompressions: []string{"none", "zlib@openssh.com"},
	}
	config.SetDefaults()
	tr := newHandshakeTransport(&kexCaptureTransport{a}, config, []byte("SSH-2.0-client"), []byte("SSH-2.0-server"))
	if err := tr.sendKexInit(); err != nil {
		t.Fatal(err)
	}
	packet, err := b.readPacket()
	if err != nil {
		t.Fatal(err)
	}
	var msg kexInitMsg
	if err := Unmarshal(packet, &msg); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(msg.KexAlgos, "sntrup761x25519-sha512@openssh.com") || !slices.Contains(msg.KexAlgos, kexStrictClient) {
		t.Fatalf("advertised kex list must be used and keep strict-KEX (Terrapin): %v", msg.KexAlgos)
	}
	if msg.MACsClientServer[0] != "umac-64-etm@openssh.com" || !slices.Contains(msg.CompressionClientServer, "zlib@openssh.com") {
		t.Fatalf("advertised MACs/compressions not used: %v %v", msg.MACsClientServer, msg.CompressionClientServer)
	}
}
