// Package sntrup761 implements the Streamlined NTRU Prime sntrup761 KEM, as
// used by OpenSSH's sntrup761x25519-sha512 key exchange. It is a direct port
// of the public domain SUPERCOP "compact" reference implementation by Daniel
// J. Bernstein, Chitchanok Chuengsatiansup, Tanja Lange and Christine van
// Vredendaal, as shipped in OpenSSH's sntrup761.c.
package sntrup761

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"io"
)

const (
	p   = 761
	q   = 4591
	w   = 286
	q12 = (q - 1) / 2

	hashBytes       = 32
	smallBytes      = (p + 3) / 4
	secretKeysBytes = 2 * smallBytes
	confirmBytes    = 32
	roundedBytes    = 1007

	PublicKeySize  = 1158
	SecretKeySize  = secretKeysBytes + PublicKeySize + smallBytes + hashBytes
	CiphertextSize = roundedBytes + confirmBytes
	SharedKeySize  = 32
)

type small = int8
type fq = int16

func int16NegativeMask(x int16) int16 { return x >> 15 }

func int16NonzeroMask(x int16) int16 { return (x | -x) >> 15 }

func f3Freeze(x int32) small {
	return small(x - 3*((10923*x+16384)>>15))
}

func fqFreeze(x int32) fq {
	const (
		q16 = (0x10000 + q/2) / q
		q20 = (0x100000 + q/2) / q
		q28 = (0x10000000 + q/2) / q
	)
	x -= q * ((q16 * x) >> 16)
	x -= q * ((q20 * x) >> 20)
	return fq(x - q*((q28*x+0x8000000)>>28))
}

func weightwMask(r *[p]small) int16 {
	weight := int16(0)
	for i := range r {
		weight += int16(r[i]) & 1
	}
	return int16NonzeroMask(weight - w)
}

func uint32DivmodUint14(x uint32, m uint16) (uint32, uint16) {
	v := uint32(0x80000000) / uint32(m)
	qpart := uint32((uint64(x) * uint64(v)) >> 31)
	x -= qpart * uint32(m)
	quot := qpart
	qpart = uint32((uint64(x) * uint64(v)) >> 31)
	x -= qpart * uint32(m)
	quot += qpart
	x -= uint32(m)
	quot++
	mask := uint32(int32(x) >> 31)
	x += mask & uint32(m)
	quot += mask
	return quot, uint16(x)
}

func uint32ModUint14(x uint32, m uint16) uint16 {
	_, r := uint32DivmodUint14(x, m)
	return r
}

func encode(out []byte, r, m []uint16) []byte {
	if len(r) == 1 {
		rr, mm := r[0], m[0]
		for mm > 1 {
			out = append(out, byte(rr))
			rr >>= 8
			mm = (mm + 255) >> 8
		}
		return out
	}
	n := len(r)
	r2 := make([]uint16, (n+1)/2)
	m2 := make([]uint16, (n+1)/2)
	i := 0
	for ; i < n-1; i += 2 {
		m0 := uint32(m[i])
		rr := uint32(r[i]) + uint32(r[i+1])*m0
		mm := uint32(m[i+1]) * m0
		for mm >= 16384 {
			out = append(out, byte(rr))
			rr >>= 8
			mm = (mm + 255) >> 8
		}
		r2[i/2] = uint16(rr)
		m2[i/2] = uint16(mm)
	}
	if i < n {
		r2[i/2] = r[i]
		m2[i/2] = m[i]
	}
	return encode(out, r2, m2)
}

func decode(out []uint16, s []byte, m []uint16) {
	n := len(m)
	if n == 1 {
		switch {
		case m[0] == 1:
			out[0] = 0
		case m[0] <= 256:
			out[0] = uint32ModUint14(uint32(s[0]), m[0])
		default:
			out[0] = uint32ModUint14(uint32(s[0])+uint32(s[1])<<8, m[0])
		}
		return
	}
	r2 := make([]uint16, (n+1)/2)
	m2 := make([]uint16, (n+1)/2)
	bottomr := make([]uint16, n/2)
	bottomt := make([]uint32, n/2)
	i := 0
	for ; i < n-1; i += 2 {
		mm := uint32(m[i]) * uint32(m[i+1])
		switch {
		case mm > 256*16383:
			bottomt[i/2] = 256 * 256
			bottomr[i/2] = uint16(s[0]) + 256*uint16(s[1])
			s = s[2:]
			m2[i/2] = uint16((((mm + 255) >> 8) + 255) >> 8)
		case mm >= 16384:
			bottomt[i/2] = 256
			bottomr[i/2] = uint16(s[0])
			s = s[1:]
			m2[i/2] = uint16((mm + 255) >> 8)
		default:
			bottomt[i/2] = 1
			bottomr[i/2] = 0
			m2[i/2] = uint16(mm)
		}
	}
	if i < n {
		m2[i/2] = m[i]
	}
	decode(r2, s, m2)
	o := 0
	for i = 0; i < n-1; i += 2 {
		rr := uint32(bottomr[i/2]) + bottomt[i/2]*uint32(r2[i/2])
		r1, r0 := uint32DivmodUint14(rr, m[i])
		out[o] = r0
		out[o+1] = uint32ModUint14(r1, m[i+1])
		o += 2
	}
	if i < n {
		out[o] = r2[i/2]
	}
}

func r3FromRq(out *[p]small, r *[p]fq) {
	for i := range out {
		out[i] = f3Freeze(int32(r[i]))
	}
}

func r3Mult(h, f, g *[p]small) {
	var fg [p + p - 1]int16
	for i := 0; i < p; i++ {
		for j := 0; j < p; j++ {
			fg[i+j] += int16(f[i]) * int16(g[j])
		}
	}
	for i := p; i < p+p-1; i++ {
		fg[i-p] += fg[i]
	}
	for i := p; i < p+p-1; i++ {
		fg[i-p+1] += fg[i]
	}
	for i := 0; i < p; i++ {
		h[i] = f3Freeze(int32(fg[i]))
	}
}

func r3Recip(out, in *[p]small) int16 {
	var f, g, v, r [p + 1]small
	delta := int32(1)
	r[0] = 1
	f[0] = 1
	f[p-1], f[p] = -1, -1
	for i := 0; i < p; i++ {
		g[p-1-i] = in[i]
	}
	for loop := 0; loop < 2*p-1; loop++ {
		for i := p; i > 0; i-- {
			v[i] = v[i-1]
		}
		v[0] = 0
		sign := -int32(g[0]) * int32(f[0])
		swap := int32(int16NegativeMask(int16(-delta)) & int16NonzeroMask(int16(g[0])))
		delta ^= swap & (delta ^ -delta)
		delta++
		for i := 0; i < p+1; i++ {
			t := small(swap) & (f[i] ^ g[i])
			f[i] ^= t
			g[i] ^= t
			t = small(swap) & (v[i] ^ r[i])
			v[i] ^= t
			r[i] ^= t
		}
		for i := 0; i < p+1; i++ {
			g[i] = f3Freeze(int32(g[i]) + sign*int32(f[i]))
		}
		for i := 0; i < p+1; i++ {
			r[i] = f3Freeze(int32(r[i]) + sign*int32(v[i]))
		}
		for i := 0; i < p; i++ {
			g[i] = g[i+1]
		}
		g[p] = 0
	}
	sign := f[0]
	for i := 0; i < p; i++ {
		out[i] = sign * v[p-1-i]
	}
	return int16NonzeroMask(int16(delta))
}

func rqMultSmall(h, f *[p]fq, g *[p]small) {
	var fg [p + p - 1]int32
	for i := 0; i < p; i++ {
		for j := 0; j < p; j++ {
			fg[i+j] += int32(f[i]) * int32(g[j])
		}
	}
	for i := p; i < p+p-1; i++ {
		fg[i-p] += fg[i]
	}
	for i := p; i < p+p-1; i++ {
		fg[i-p+1] += fg[i]
	}
	for i := 0; i < p; i++ {
		h[i] = fqFreeze(fg[i])
	}
}

func rqMult3(h, f *[p]fq) {
	for i := range h {
		h[i] = fqFreeze(3 * int32(f[i]))
	}
}

func fqRecip(a1 fq) fq {
	ai := a1
	for i := 1; i < q-2; i++ {
		ai = fqFreeze(int32(a1) * int32(ai))
	}
	return ai
}

func rqRecip3(out *[p]fq, in *[p]small) int16 {
	var f, g, v, r [p + 1]fq
	delta := int32(1)
	r[0] = fqRecip(3)
	f[0] = 1
	f[p-1], f[p] = -1, -1
	for i := 0; i < p; i++ {
		g[p-1-i] = fq(in[i])
	}
	for loop := 0; loop < 2*p-1; loop++ {
		for i := p; i > 0; i-- {
			v[i] = v[i-1]
		}
		v[0] = 0
		swap := int32(int16NegativeMask(int16(-delta)) & int16NonzeroMask(g[0]))
		delta ^= swap & (delta ^ -delta)
		delta++
		for i := 0; i < p+1; i++ {
			t := fq(swap) & (f[i] ^ g[i])
			f[i] ^= t
			g[i] ^= t
			t = fq(swap) & (v[i] ^ r[i])
			v[i] ^= t
			r[i] ^= t
		}
		f0, g0 := int32(f[0]), int32(g[0])
		for i := 0; i < p+1; i++ {
			g[i] = fqFreeze(f0*int32(g[i]) - g0*int32(f[i]))
		}
		for i := 0; i < p+1; i++ {
			r[i] = fqFreeze(f0*int32(r[i]) - g0*int32(v[i]))
		}
		for i := 0; i < p; i++ {
			g[i] = g[i+1]
		}
		g[p] = 0
	}
	scale := int32(fqRecip(f[0]))
	for i := 0; i < p; i++ {
		out[i] = fqFreeze(scale * int32(v[p-1-i]))
	}
	return int16NonzeroMask(int16(delta))
}

func round(out, a *[p]fq) {
	for i := range out {
		out[i] = a[i] - fq(f3Freeze(int32(a[i])))
	}
}

func int32MinMax(a, b *int32) {
	x, y := *a, *b
	m := int32((int64(y) - int64(x)) >> 63)
	t := (x ^ y) & m
	*a, *b = x^t, y^t
}

func sortInt32(x []int32) {
	n := len(x)
	if n < 2 {
		return
	}
	top := 1
	for top < n-top {
		top += top
	}
	for pp := top; pp >= 1; pp >>= 1 {
		i := 0
		for i+2*pp <= n {
			for j := i; j < i+pp; j++ {
				int32MinMax(&x[j], &x[j+pp])
			}
			i += 2 * pp
		}
		for j := i; j < n-pp; j++ {
			int32MinMax(&x[j], &x[j+pp])
		}
		i = 0
		j := 0
	outer:
		for qq := top; qq > pp; qq >>= 1 {
			if j != i {
				for {
					if j == n-qq {
						continue outer
					}
					a := x[j+pp]
					for r := qq; r > pp; r >>= 1 {
						int32MinMax(&a, &x[j+r])
					}
					x[j+pp] = a
					j++
					if j == i+pp {
						i += 2 * pp
						break
					}
				}
			}
			for i+pp <= n-qq {
				for j = i; j < i+pp; j++ {
					a := x[j+pp]
					for r := qq; r > pp; r >>= 1 {
						int32MinMax(&a, &x[j+r])
					}
					x[j+pp] = a
				}
				i += 2 * pp
			}
			j = i
			for j < n-qq {
				a := x[j+pp]
				for r := qq; r > pp; r >>= 1 {
					int32MinMax(&a, &x[j+r])
				}
				x[j+pp] = a
				j++
			}
		}
	}
}

func sortUint32(x []uint32) {
	s := make([]int32, len(x))
	for i, v := range x {
		s[i] = int32(v ^ 0x80000000)
	}
	sortInt32(s)
	for i, v := range s {
		x[i] = uint32(v) ^ 0x80000000
	}
}

func shortFromList(out *[p]small, in []uint32) {
	var l [p]uint32
	for i := 0; i < w; i++ {
		l[i] = in[i] &^ 1
	}
	for i := w; i < p; i++ {
		l[i] = (in[i] &^ 2) | 1
	}
	sortUint32(l[:])
	for i := range out {
		out[i] = small(l[i]&3) - 1
	}
}

func hashPrefix(b byte, in []byte) [hashBytes]byte {
	h := sha512.New()
	h.Write([]byte{b})
	h.Write(in)
	var out [hashBytes]byte
	copy(out[:], h.Sum(nil))
	return out
}

func randomUint32s(rand io.Reader) ([]uint32, error) {
	buf := make([]byte, 4*p)
	if _, err := io.ReadFull(rand, buf); err != nil {
		return nil, err
	}
	l := make([]uint32, p)
	for i := range l {
		l[i] = binary.LittleEndian.Uint32(buf[4*i:])
	}
	return l, nil
}

func shortRandom(out *[p]small, rand io.Reader) error {
	l, err := randomUint32s(rand)
	if err != nil {
		return err
	}
	shortFromList(out, l)
	return nil
}

func smallRandom(out *[p]small, rand io.Reader) error {
	l, err := randomUint32s(rand)
	if err != nil {
		return err
	}
	for i := range out {
		out[i] = small(((l[i]&0x3fffffff)*3)>>30) - 1
	}
	return nil
}

func keyGen(h *[p]fq, f, ginv *[p]small, rand io.Reader) error {
	var g [p]small
	for {
		if err := smallRandom(&g, rand); err != nil {
			return err
		}
		if r3Recip(ginv, &g) == 0 {
			break
		}
	}
	if err := shortRandom(f, rand); err != nil {
		return err
	}
	var finv [p]fq
	rqRecip3(&finv, f)
	rqMultSmall(h, &finv, &g)
	return nil
}

func encrypt(c *[p]fq, r *[p]small, h *[p]fq) {
	var hr [p]fq
	rqMultSmall(&hr, h, r)
	round(c, &hr)
}

func decrypt(r *[p]small, c *[p]fq, f, ginv *[p]small) {
	var cf, cf3 [p]fq
	var e, ev [p]small
	rqMultSmall(&cf, c, f)
	rqMult3(&cf3, &cf)
	r3FromRq(&e, &cf3)
	r3Mult(&ev, &e, ginv)
	mask := small(weightwMask(&ev))
	for i := 0; i < w; i++ {
		r[i] = ((ev[i] ^ 1) &^ mask) ^ 1
	}
	for i := w; i < p; i++ {
		r[i] = ev[i] &^ mask
	}
}

func smallEncode(s []byte, f *[p]small) {
	k := 0
	for i := 0; i < p/4; i++ {
		var x byte
		for j := 0; j < 4; j++ {
			x += byte(f[k]+1) << (2 * j)
			k++
		}
		s[i] = x
	}
	s[p/4] = byte(f[k] + 1)
}

func smallDecode(f *[p]small, s []byte) {
	k := 0
	for i := 0; i < p/4; i++ {
		x := s[i]
		for j := 0; j < 4; j++ {
			f[k] = small((x>>(2*j))&3) - 1
			k++
		}
	}
	f[k] = small(s[p/4]&3) - 1
}

func rqEncode(r *[p]fq) []byte {
	var rr, m [p]uint16
	for i := range rr {
		rr[i] = uint16(int32(r[i]) + q12)
		m[i] = q
	}
	return encode(make([]byte, 0, PublicKeySize), rr[:], m[:])
}

func rqDecode(r *[p]fq, s []byte) {
	var rr, m [p]uint16
	for i := range m {
		m[i] = q
	}
	decode(rr[:], s, m[:])
	for i := range r {
		r[i] = fq(int32(rr[i]) - q12)
	}
}

func roundedEncode(r *[p]fq) []byte {
	var rr, m [p]uint16
	for i := range rr {
		rr[i] = uint16(((int32(r[i]) + q12) * 10923) >> 15)
		m[i] = (q + 2) / 3
	}
	return encode(make([]byte, 0, roundedBytes), rr[:], m[:])
}

func roundedDecode(r *[p]fq, s []byte) {
	var rr, m [p]uint16
	for i := range m {
		m[i] = (q + 2) / 3
	}
	decode(rr[:], s, m[:])
	for i := range r {
		r[i] = fq(int32(rr[i])*3 - q12)
	}
}

func hashConfirm(rEnc []byte, cache []byte) [hashBytes]byte {
	var x [2 * hashBytes]byte
	h := hashPrefix(3, rEnc)
	copy(x[:], h[:])
	copy(x[hashBytes:], cache)
	return hashPrefix(2, x[:])
}

func hashSession(b byte, y, z []byte) [hashBytes]byte {
	x := make([]byte, hashBytes+CiphertextSize)
	h := hashPrefix(3, y)
	copy(x, h[:])
	copy(x[hashBytes:], z)
	return hashPrefix(b, x)
}

// GenerateKey returns a new key pair: the public key (PublicKeySize bytes)
// and the secret key (SecretKeySize bytes).
func GenerateKey(rand io.Reader) (pk, sk []byte, err error) {
	var h [p]fq
	var f, v [p]small
	if err := keyGen(&h, &f, &v, rand); err != nil {
		return nil, nil, err
	}
	pk = rqEncode(&h)
	sk = make([]byte, SecretKeySize)
	smallEncode(sk, &f)
	smallEncode(sk[smallBytes:], &v)
	copy(sk[secretKeysBytes:], pk)
	rho := sk[secretKeysBytes+PublicKeySize:]
	if _, err := io.ReadFull(rand, rho[:smallBytes]); err != nil {
		return nil, nil, err
	}
	cache := hashPrefix(4, pk)
	copy(rho[smallBytes:], cache[:])
	return pk, sk, nil
}

func hide(r *[p]small, pk, cache []byte) (c, rEnc []byte) {
	rEnc = make([]byte, smallBytes)
	smallEncode(rEnc, r)
	var h, cc [p]fq
	rqDecode(&h, pk)
	encrypt(&cc, r, &h)
	c = roundedEncode(&cc)
	confirm := hashConfirm(rEnc, cache)
	return append(c, confirm[:]...), rEnc
}

// Encapsulate returns a ciphertext and the shared key it carries for pk.
func Encapsulate(rand io.Reader, pk []byte) (ct, key []byte, err error) {
	if len(pk) != PublicKeySize {
		return nil, nil, io.ErrUnexpectedEOF
	}
	cache := hashPrefix(4, pk)
	var r [p]small
	if err := shortRandom(&r, rand); err != nil {
		return nil, nil, err
	}
	ct, rEnc := hide(&r, pk, cache[:])
	k := hashSession(1, rEnc, ct)
	return ct, k[:], nil
}

// Decapsulate returns the shared key carried by ct. A malformed ciphertext
// yields a pseudorandom key (implicit rejection), as in the reference code.
func Decapsulate(sk, ct []byte) ([]byte, error) {
	if len(sk) != SecretKeySize || len(ct) != CiphertextSize {
		return nil, io.ErrUnexpectedEOF
	}
	pk := sk[secretKeysBytes : secretKeysBytes+PublicKeySize]
	rho := sk[secretKeysBytes+PublicKeySize : secretKeysBytes+PublicKeySize+smallBytes]
	cache := sk[secretKeysBytes+PublicKeySize+smallBytes:]
	var f, v, r [p]small
	var c [p]fq
	smallDecode(&f, sk)
	smallDecode(&v, sk[smallBytes:])
	roundedDecode(&c, ct)
	decrypt(&r, &c, &f, &v)
	cnew, rEnc := hide(&r, pk, cache)
	equal := subtle.ConstantTimeCompare(ct, cnew)
	subtle.ConstantTimeCopy(1-equal, rEnc, rho)
	k := hashSession(byte(equal), rEnc, ct)
	return k[:], nil
}
