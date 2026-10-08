// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var sntrupNames = []string{KeyExchangeSNTRUP761X25519, KeyExchangeSNTRUP761X25519OpenSSH}

func sntrupTestServer(t *testing.T, kex string) (string, *ServerConfig) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ServerConfig{NoClientAuth: true, Config: Config{KeyExchanges: []string{kex}}}
	cfg.AddHostKey(signer)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go DiscardRequests(reqs)
				for nc := range chans {
					nc.Reject(Prohibited, "")
				}
				sc.Close()
			}()
		}
	}()
	return lis.Addr().String(), cfg
}

func TestSNTRUP761KexGoToGo(t *testing.T) {
	for _, kex := range sntrupNames {
		addr, _ := sntrupTestServer(t, kex)
		c, err := Dial("tcp", addr, &ClientConfig{
			Config:          Config{KeyExchanges: []string{kex}},
			HostKeyCallback: InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		})
		if err != nil {
			t.Fatalf("%s: %v", kex, err)
		}
		c.Close()
	}
}

func TestSNTRUP761KexWithOpenSSHClient(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no OpenSSH client")
	}
	for _, kex := range sntrupNames {
		addr, _ := sntrupTestServer(t, kex)
		host, port, _ := net.SplitHostPort(addr)
		out, _ := exec.Command(sshBin, "-v", "-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null", "-o", "KexAlgorithms="+kex, "-o", "ConnectTimeout=5",
			"-o", "ExitOnForwardFailure=yes", "-p", port, "-W", "127.0.0.1:1", "probe@"+host).CombinedOutput()
		log := string(out)
		if !strings.Contains(log, "kex: algorithm: "+kex) || !strings.Contains(log, "Authenticated to") {
			t.Fatalf("%s: OpenSSH client did not complete the key exchange:\n%s", kex, log)
		}
	}
}

func TestSNTRUP761KexWithOpenSSHServer(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second)
	if err != nil {
		t.Skip("no local sshd")
	}
	conn.Close()
	for _, kex := range sntrupNames {
		var negotiated bool
		_, err := Dial("tcp", "127.0.0.1:22", &ClientConfig{
			User:   "sntrup-probe",
			Config: Config{KeyExchanges: []string{kex}},
			HostKeyCallback: func(string, net.Addr, PublicKey) error {
				negotiated = true
				return nil
			},
			Timeout: 5 * time.Second,
		})
		if !negotiated || err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("%s: key exchange with OpenSSH sshd failed: %v", kex, err)
		}
	}
}

func TestServerAcceptsClientExtInfoFromOpenSSH(t *testing.T) {
	sshBin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("no OpenSSH client")
	}
	addr, cfg := sntrupTestServer(t, KeyExchangeCurve25519)
	cfg.AdvertisedKeyExchanges = []string{KeyExchangeCurve25519, "ext-info-s"}
	host, port, _ := net.SplitHostPort(addr)
	out, _ := exec.Command(sshBin, "-v", "-N", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-p", port, "-W", "127.0.0.1:1",
		"probe@"+host).CombinedOutput()
	log := string(out)
	if !strings.Contains(log, "Sending SSH2_MSG_EXT_INFO") || !strings.Contains(log, "Authenticated to") {
		t.Fatalf("server must accept the client's EXT_INFO after advertising ext-info-s:\n%s", log)
	}
	if !strings.Contains(log, "publickey-hostbound@openssh.com=<0>") || !strings.Contains(log, "ping@openssh.com=<0>") {
		t.Fatalf("server EXT_INFO does not carry OpenSSH's extensions:\n%s", log)
	}
}
