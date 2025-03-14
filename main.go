package main

import (
	"encoding/hex"
	"errors"
	"fmt"

	blsGnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	blsSon "github.com/supranational/blst/bindings/go"
)

var (
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
)

func main() {

	pubKey, signature := blsSonic()

	g1 := blsSon.P1Generator()
	msg := []byte("Hello")
	msgG2 := blsSon.HashToG2(msg, nil)

	input, err := getInputForPrecompiledContract(
		[]blsSon.P1Affine{*g1.ToAffine(), *pubKey},
		[]blsSon.P2Affine{*signature, *msgG2.ToAffine()},
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("input:", hex.EncodeToString(input))

}

// getInputPQ returns input bytes for pairing function e(p, q) used in precompiled contract
func getInputPQ(p *blsSon.P1Affine, q *blsSon.P2Affine) []byte {

	keyPoint := new(blsGnark.G1Affine)
	keyPoint.SetBytes(p.Compress())
	keyBytes := encodePointG1(keyPoint)

	sigPoint := new(blsGnark.G2Affine)
	sigPoint.SetBytes(q.Compress())
	sigBytes := encodePointG2(sigPoint)
	return append(keyBytes, sigBytes...)
}

func getInputForPrecompiledContract(p []blsSon.P1Affine, q []blsSon.P2Affine) ([]byte, error) {

	if len(p) == 0 || len(p) != len(q) {
		return nil, errors.New("invalid input length")
	}

	// for every point pair compute input for pairing function
	input := make([]byte, 0)
	for i := 0; i < len(p); i++ {
		input = append(input, getInputPQ(&p[i], &q[i])...)
	}

	return input, nil
}

func blsSonic() (*blsSon.P1Affine, *blsSon.P2Affine) {

	msg := []byte("Hello")
	msgG2 := blsSon.HashToG2(msg, nil)

	// hashedMsg := blst.P2Generator()
	// hashedMsg.ToAffine().Print("hashedMsg")

	g1 := blsSon.P1Generator()

	scalar := []byte{3}
	pubKey := g1.Mult(scalar)

	g1.ToAffine().Print("g1")
	pubKey.ToAffine().Print("pubKey")

	signature := msgG2.Mult(scalar)
	signature.ToAffine().Print("signature")

	fmt.Println("pubkey", hex.EncodeToString(pubKey.ToAffine().Compress()))
	fmt.Println("signature", hex.EncodeToString(signature.ToAffine().Compress()))

	ok := signature.ToAffine().Verify(true, pubKey.ToAffine(), true, msg, nil)

	fmt.Println("is ok:", ok)

	return pubKey.ToAffine(), signature.ToAffine()

}

func decodeString(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Generator points from https://eips.ethereum.org/EIPS/eip-2537
//
// G1:
// X = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
// Y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
// G2:
// X c0 = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
// X c1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
// Y c0 = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
// Y c1 = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
func generatorG1FromSpecs() *blsGnark.G1Affine {
	cX := decodeString("17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
	cY := decodeString("08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1")

	g1 := new(blsGnark.G1Affine)

	g1.X.SetBytes(cX)
	g1.Y.SetBytes(cY)

	return g1
}

func generatorG2FromSpecs() *blsGnark.G2Affine {

	c0X := decodeString("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
	c0Y := decodeString("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")
	c1X := decodeString("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e")
	c1Y := decodeString("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be")

	g2 := new(blsGnark.G2Affine)
	g2.X.A0.SetBytes(c0X)
	g2.X.A1.SetBytes(c1X)
	g2.Y.A0.SetBytes(c0Y)
	g2.Y.A1.SetBytes(c1Y)

	return g2
}

func decodePointG1(in []byte) (*blsGnark.G1Affine, error) {
	if len(in) != 128 {
		return nil, errors.New("invalid g1 point length")
	}
	// decode x
	x, err := decodeBLS12381FieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	// decode y
	y, err := decodeBLS12381FieldElement(in[64:])
	if err != nil {
		return nil, err
	}
	elem := blsGnark.G1Affine{X: x, Y: y}
	if !elem.IsOnCurve() {
		return nil, errors.New("invalid point: not on curve")
	}

	return &elem, nil
}

// decodePointG2 given encoded (x, y) coordinates in 256 bytes returns a valid G2 Point.
func decodePointG2(in []byte) (*blsGnark.G2Affine, error) {
	if len(in) != 256 {
		return nil, errors.New("invalid g2 point length")
	}
	x0, err := decodeBLS12381FieldElement(in[:64])
	if err != nil {
		return nil, err
	}
	x1, err := decodeBLS12381FieldElement(in[64:128])
	if err != nil {
		return nil, err
	}
	y0, err := decodeBLS12381FieldElement(in[128:192])
	if err != nil {
		return nil, err
	}
	y1, err := decodeBLS12381FieldElement(in[192:])
	if err != nil {
		return nil, err
	}

	p := blsGnark.G2Affine{X: blsGnark.E2{A0: x0, A1: x1}, Y: blsGnark.E2{A0: y0, A1: y1}}
	if !p.IsOnCurve() {
		return nil, errors.New("invalid point: not on curve")
	}
	return &p, err
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) (fp.Element, error) {
	if len(in) != 64 {
		return fp.Element{}, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return fp.Element{}, errBLS12381InvalidFieldElementTopBytes
		}
	}
	var res [48]byte
	copy(res[:], in[16:])

	return fp.BigEndian.Element(&res)
}

// encodePointG1 encodes a point into 128 bytes.
func encodePointG1(p *blsGnark.G1Affine) []byte {
	out := make([]byte, 128)
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[16:]), p.X)
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[64+16:]), p.Y)
	return out
}

// encodePointG2 encodes a point into 256 bytes.
func encodePointG2(p *blsGnark.G2Affine) []byte {
	out := make([]byte, 256)
	// encode x
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[16:16+48]), p.X.A0)
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[80:80+48]), p.X.A1)
	// encode y
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[144:144+48]), p.Y.A0)
	fp.BigEndian.PutElement((*[fp.Bytes]byte)(out[208:208+48]), p.Y.A1)
	return out
}
