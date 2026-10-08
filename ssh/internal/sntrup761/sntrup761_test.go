package sntrup761

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"slices"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for i := 0; i < 20; i++ {
		pk, sk, err := GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if len(pk) != PublicKeySize || len(sk) != SecretKeySize {
			t.Fatalf("sizes: pk=%d sk=%d", len(pk), len(sk))
		}
		ct, k1, err := Encapsulate(rand.Reader, pk)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct) != CiphertextSize || len(k1) != SharedKeySize {
			t.Fatalf("sizes: ct=%d k=%d", len(ct), len(k1))
		}
		k2, err := Decapsulate(sk, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k1, k2) {
			t.Fatalf("iteration %d: shared keys differ", i)
		}
	}
}

func TestTamperedCiphertextIsImplicitlyRejected(t *testing.T) {
	pk, sk, _ := GenerateKey(rand.Reader)
	ct, k, _ := Encapsulate(rand.Reader, pk)
	ct[10] ^= 1
	bad, err := Decapsulate(sk, ct)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(bad, k) {
		t.Fatal("a tampered ciphertext must not yield the shared key")
	}
	again, _ := Decapsulate(sk, ct)
	if !bytes.Equal(bad, again) {
		t.Fatal("implicit rejection must be deterministic")
	}
}

func TestSortMatchesStandardSort(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 7, 64, 100, 761, 1000} {
		x := make([]uint32, n)
		for i := range x {
			x[i] = mrand.Uint32()
		}
		if n > 4 {
			x[0], x[1] = 0, 0xffffffff
		}
		want := slices.Clone(x)
		slices.Sort(want)
		sortUint32(x)
		if !slices.Equal(x, want) {
			t.Fatalf("n=%d: constant-time sort disagrees with slices.Sort", n)
		}
	}
}
