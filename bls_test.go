package main

import (
	"fmt"
	"math/big"
	"testing"

	blsGnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/stretchr/testify/require"
	blsSon "github.com/supranational/blst/bindings/go"
)

func TestBLS(t *testing.T) {

	tests := map[string]struct {
		inputFromEthTests []byte
		p                 []blsGnark.G1Affine
		q                 []blsGnark.G2Affine
	}{
		"bls_pairing_e(2*G1,3*G2)=e(6*G1,G2)": {
			// https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/blsPairing.json
			inputFromEthTests: decodeString("000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d2800000000000000000000000000000000122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae0000000000000000000000000000000009380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc000000000000000000000000000000000b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd8920000000000000000000000000000000008f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e8490000000000000000000000000000000006e82f6da4520f85c5d27d8f329eccfa05944fd1096b20734c894966d12a9e2a9a9744529d7212d33883113a0cadb9090000000000000000000000000000000017d81038f7d60bee9110d9c0d6d1102fe2d998c957f28e31ec284cc04134df8e47e8f82ff3af2e60a6d9688a4563477c00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed"),

			// new points according to test name formula e(p[0],q[0])=e(p[1],q[1])
			p: []blsGnark.G1Affine{
				*generatorG1FromSpecs().ScalarMultiplication(generatorG1FromSpecs(), big.NewInt(2)),
				*generatorG1FromSpecs().ScalarMultiplication(generatorG1FromSpecs(), big.NewInt(6)),
			},
			q: []blsGnark.G2Affine{
				*generatorG2FromSpecs().ScalarMultiplication(generatorG2FromSpecs(), big.NewInt(3)),
				*generatorG2FromSpecs().ScalarMultiplication(generatorG2FromSpecs(), big.NewInt(1)),
			},
		},
		"valid in different library": {
			inputFromEthTests: getTestData([]byte("Hello, world"), []byte{3}),
			p: []blsGnark.G1Affine{
				*generatorG1FromSpecs().ScalarMultiplication(generatorG1FromSpecs(), big.NewInt(1)),
				*generatorG1FromSpecs().ScalarMultiplication(generatorG1FromSpecs(), big.NewInt(2)),
			},
			q: []blsGnark.G2Affine{
				*generatorG2FromSpecs().ScalarMultiplication(generatorG2FromSpecs(), big.NewInt(1)),
				*generatorG2FromSpecs().ScalarMultiplication(generatorG2FromSpecs(), big.NewInt(2)),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testBLS(t, test.inputFromEthTests, test.p, test.q)
		})
	}
}

func TestBLSOnlyInputData(t *testing.T) {

	tests := map[string]struct {
		input []byte
	}{
		"bls_pairing_e(2*G1,3*G2)=e(6*G1,G2)": {
			// https://github.com/ethereum/go-ethereum/blob/master/core/vm/testdata/precompiles/blsPairing.json
			input: decodeString("000000000000000000000000000000000572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e00000000000000000000000000000000166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d2800000000000000000000000000000000122915c824a0857e2ee414a3dccb23ae691ae54329781315a0c75df1c04d6d7a50a030fc866f09d516020ef82324afae0000000000000000000000000000000009380275bbc8e5dcea7dc4dd7e0550ff2ac480905396eda55062650f8d251c96eb480673937cc6d9d6a44aaa56ca66dc000000000000000000000000000000000b21da7955969e61010c7a1abc1a6f0136961d1e3b20b1a7326ac738fef5c721479dfd948b52fdf2455e44813ecfd8920000000000000000000000000000000008f239ba329b3967fe48d718a36cfe5f62a7e42e0bf1c1ed714150a166bfbd6bcf6b3b58b975b9edea56d53f23a0e8490000000000000000000000000000000006e82f6da4520f85c5d27d8f329eccfa05944fd1096b20734c894966d12a9e2a9a9744529d7212d33883113a0cadb9090000000000000000000000000000000017d81038f7d60bee9110d9c0d6d1102fe2d998c957f28e31ec284cc04134df8e47e8f82ff3af2e60a6d9688a4563477c00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed"),
		},
		"should be valid": {
			input: getTestData([]byte("Hello, world"), []byte{3}),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testBLSInput(t, test.input)
		})
	}
}

func getTestData(msg []byte, pk []byte) []byte {

	// g1 generator
	g1 := blsSon.P1Generator()

	// msg to point G2
	msgG2 := blsSon.HashToG2(msg, nil)

	// pubkey point G1
	pubKeyG1 := g1.Mult(pk)

	// signatureG2 point G2
	signatureG2 := msgG2.Mult(pk)

	input, err := getInputForPrecompiledContract(
		[]blsSon.P1Affine{*g1.ToAffine(), *pubKeyG1.ToAffine()},
		[]blsSon.P2Affine{*signatureG2.ToAffine(), *msgG2.ToAffine()},
	)
	if err != nil {
		panic(err)
	}

	return input
}

func testBLSInput(t *testing.T, input []byte) {
	require := require.New(t)
	// Decode input from eth pairing tests
	p, q := decodeInput(input)

	// compute pairings groups e(p[0], q[0]) and e(p[1], q[1])
	gt0, err := blsGnark.Pair([]blsGnark.G1Affine{p[0]}, []blsGnark.G2Affine{q[0]})
	if err != nil {
		panic(err)
	}
	gt1, err := blsGnark.Pair([]blsGnark.G1Affine{p[1]}, []blsGnark.G2Affine{q[1]})
	if err != nil {
		panic(err)
	}

	fmt.Printf("gt compared: %v\n", gt0.Equal(&gt1))
	require.Equal(gt0, gt1)

	// compute pairing check - function used in go-ethereum precompiled contract
	pairCheck, err := blsGnark.PairingCheck(p, q)
	if err != nil {
		panic(err)
	}

	fmt.Printf("pair check decoded: %v\n", pairCheck)
	require.True(pairCheck)

}

func testBLS(t *testing.T, input []byte, p []blsGnark.G1Affine, q []blsGnark.G2Affine) {

	// Decode input from eth pairing tests
	pDecoded, qDecoded := decodeInput(input)

	// compare points to expected
	for i := 0; i < len(p); i++ {
		fmt.Printf("compare p[%v] and pDecoded[%v]: %v\n", i, i, p[i].Equal(&pDecoded[i]))
		fmt.Printf("compare q[%v] and qDecoded[%v]: %v\n", i, i, q[i].Equal(&qDecoded[i]))
	}

	// compute separate pairings
	gtDecoded0, err := blsGnark.Pair([]blsGnark.G1Affine{pDecoded[0]}, []blsGnark.G2Affine{qDecoded[0]})
	if err != nil {
		panic(err)
	}

	gtDecoded1, err := blsGnark.Pair([]blsGnark.G1Affine{pDecoded[1]}, []blsGnark.G2Affine{qDecoded[1]})
	if err != nil {
		panic(err)
	}

	fmt.Printf("gt compared: %v\n", gtDecoded0.Equal(&gtDecoded1))

	gtExpected0, err := blsGnark.Pair([]blsGnark.G1Affine{p[0]}, []blsGnark.G2Affine{q[0]})
	if err != nil {
		panic(err)
	}

	gtExpected1, err := blsGnark.Pair([]blsGnark.G1Affine{p[1]}, []blsGnark.G2Affine{q[1]})
	if err != nil {
		panic(err)
	}

	fmt.Printf("gt compared expected: %v\n", gtExpected0.Equal(&gtExpected1))

	// compute pairing check - function used in go-ethereum precompiled contract
	pairCheckDecoded, err := blsGnark.PairingCheck(pDecoded, qDecoded)
	if err != nil {
		panic(err)
	}
	pairCheckExpected, err := blsGnark.PairingCheck(p, q)
	if err != nil {
		panic(err)
	}

	fmt.Printf("pair check decoded: %v\n", pairCheckDecoded)
	fmt.Printf("pair check expected: %v\n", pairCheckExpected)
}

func decodeInput(input []byte) ([]blsGnark.G1Affine, []blsGnark.G2Affine) {
	var p []blsGnark.G1Affine
	var q []blsGnark.G2Affine

	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		fmt.Println("invalid input length")
		panic("invalid input length")
	}

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := decodePointG1(input[t0:t1])
		if err != nil {
			fmt.Println("error decoding payload G1", err)
			panic("error decoding payload G1")
		}
		// Decode G2 point
		q1, err := decodePointG2(input[t1:t2])
		if err != nil {
			fmt.Println("error decoding payload G2", err)
			panic("error decoding payload G2")
		}

		p = append(p, *p1)
		q = append(q, *q1)
	}
	return p, q
}
