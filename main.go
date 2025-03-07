package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

var (
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
)

func main() {

	input, err := hex.DecodeString("000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d2800000000000000000000000000000000122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae0000000000000000000000000000000009380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc000000000000000000000000000000000b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd8920000000000000000000000000000000008f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e8490000000000000000000000000000000006e82f6da4520f85c5d27d8f329eccfa05944fd1096b20734c894966d12a9e2a9a9744529d7212d33883113a0cadb9090000000000000000000000000000000017d81038f7d60bee9110d9c0d6d1102fe2d998c957f28e31ec284cc04134df8e47e8f82ff3af2e60a6d9688a4563477c00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed")
	if err != nil {
		fmt.Println("error decoding payload ", err)
		return
	}
	fmt.Println("input length:", len(input))

	var (
		p []bls12381.G1Affine
		q []bls12381.G2Affine

		p2 []bls12381.G1Affine
		q2 []bls12381.G2Affine
	)

	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		fmt.Println("invalid input length")
		return
	}

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := decodePointG1(input[t0:t1])
		if err != nil {
			fmt.Println("error decoding payload G1", err)
			return
		}
		// Decode G2 point
		p2, err := decodePointG2(input[t1:t2])
		if err != nil {
			fmt.Println("error decoding payload G2", err)
			return
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !p1.IsInSubGroup() {
			fmt.Println("g1 point is not on correct subgroup")
			return
		}
		if !p2.IsInSubGroup() {
			fmt.Println("g2 point is not on correct subgroup")
			return
		}
		p = append(p, *p1)
		q = append(q, *p2)
	}

	// G1 generator point 2
	e1_1 := new(bls12381.G1Affine)
	e1_1.ScalarMultiplicationBase(big.NewInt(2))

	e1_2 := new(bls12381.G2Affine)
	e1_2.ScalarMultiplicationBase(big.NewInt(3))

	e2_1 := new(bls12381.G1Affine)
	e2_1.ScalarMultiplicationBase(big.NewInt(6))

	e2_2 := new(bls12381.G2Affine)
	e2_2.ScalarMultiplicationBase(big.NewInt(1))

	p2 = append(p2, *e1_1)
	q2 = append(q2, *e1_2)
	p2 = append(p2, *e2_1)
	q2 = append(q2, *e2_2)

	fmt.Println("p[0] compare p2[0]:", p[0].Equal(&p2[0]))
	fmt.Println("q[0] compare q2[0]:", q[0].Equal(&q2[0]))
	fmt.Println("p[1] compare p2[1]:", p[1].Equal(&p2[1]))
	fmt.Println("q[1] compare q2[1]:", q[1].Equal(&q2[1]))

	fmt.Println("q[1] X:", q[1].X.String())
	fmt.Println("q[1] Y:", q[1].Y.String())
	fmt.Println("q2[1] X:", q2[1].X.String())
	fmt.Println("q2[1] Y:", q2[1].Y.String())

	fmt.Println("q[1] is in subgroup:", q[1].IsInSubGroup())
	fmt.Println("q2[1] is in subgroup:", q2[1].IsInSubGroup())

	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	ok, err := bls12381.PairingCheck(p, q)
	if err == nil && ok {
		out[31] = 1
	}

	// Compute pairing and set the result
	ok2, err := bls12381.PairingCheck(p2, q2)
	if err == nil && ok {
		out[31] = 1
	}

	fmt.Println("ok:", ok)
	fmt.Println("ok2:", ok2)
}

func decodePointG1(in []byte) (*bls12381.G1Affine, error) {
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
	elem := bls12381.G1Affine{X: x, Y: y}
	if !elem.IsOnCurve() {
		return nil, errors.New("invalid point: not on curve")
	}

	return &elem, nil
}

// decodePointG2 given encoded (x, y) coordinates in 256 bytes returns a valid G2 Point.
func decodePointG2(in []byte) (*bls12381.G2Affine, error) {
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

	p := bls12381.G2Affine{X: bls12381.E2{A0: x0, A1: x1}, Y: bls12381.E2{A0: y0, A1: y1}}
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
