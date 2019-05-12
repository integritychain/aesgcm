package aesgcm

// Internal tests for aes.go and gcm.go
// go test aesgcm.go aes.go gcm.go tables.go aesgcm_internal_test.go -coverprofile cover.out
//

// See "FIPS PUB 197" at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// See "NIST SP800-38D" at https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// See "GCM Operation" at http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

import (
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime/debug"
	"testing"
)

//
// Testing utils
//

func assertEqualsString(t *testing.T, expected string, actual string) {
	if expected != actual {
		t.Error(fmt.Sprintf("\nExpected   %v\nActual --> %v\n", expected, actual))
		t.Logf(string(debug.Stack()))
	}
}

//
// AES key expansion internals
//

func Test_aes_rotWord(t *testing.T) {
	var rot uint32
	rot = rotWord(0x09cf4f3c)
	actual := fmt.Sprintf("%08x", rot)
	assertEqualsString(t, "cf4f3c09", actual) // FIPS PUB 197, Appendix A.1, pg 27, i=4
}

func Test_aes_subWord(t *testing.T) {
	var sub uint32
	sub = subWord(0xcf4f3c09)
	actual := fmt.Sprintf("%08x", sub)
	assertEqualsString(t, "8a84eb01", actual) // FIPS PUB 197, Appendix A.1, pg 27, i=4
}

//
// AES key expansion
//

func Test_aes_keyExpansion_128(t *testing.T) {
	var instance *aesgcm
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	instance = new(aesgcm).expandAesKey(key)
	actual := fmt.Sprintf("%08x - %08x", instance.expandedAesKey[3], instance.expandedAesKey[43])
	assertEqualsString(t, "09cf4f3c - b6630ca6", actual) // FIPS PUB 197, Appendix A.1, pg 27,28
}

func Test_aes_keyExpansion_192(t *testing.T) {
	var instance *aesgcm
	key, _ := hex.DecodeString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
	instance = new(aesgcm).expandAesKey(key)
	actual := fmt.Sprintf("%08x - %08x", instance.expandedAesKey[3], instance.expandedAesKey[51])
	assertEqualsString(t, "809079e5 - 01002202", actual) // FIPS PUB 197, Appendix A.2, pg 28,30
}

func Test_aes_keyExpansion_256(t *testing.T) {
	var instance *aesgcm
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	instance = new(aesgcm).expandAesKey(key)
	actual := fmt.Sprintf("%08x - %08x", instance.expandedAesKey[3], instance.expandedAesKey[59])
	assertEqualsString(t, "857d7781 - 706c631e", actual) // FIPS PUB 197, Appendix A.3, pg 30,32
}

//
// AES cipher internals
//

func Test_aes_xtime(t *testing.T) {
	var xt byte

	xt = xtime(0x57)
	actual1 := fmt.Sprintf("%02x", xt)
	assertEqualsString(t, "ae", actual1) // FIPS PUB 197, Section 4.2.1, pg 12

	xt = xtime(0xae)
	actual2 := fmt.Sprintf("%02x", xt)
	assertEqualsString(t, "47", actual2) // FIPS PUB 197, Section 4.2.1, pg 12

	xt = xtime(0x47)
	actual3 := fmt.Sprintf("%02x", xt)
	assertEqualsString(t, "8e", actual3) // FIPS PUB 197, Section 4.2.1, pg 12

	xt = xtime(0x8e)
	actual4 := fmt.Sprintf("%02x", xt)
	assertEqualsString(t, "07", actual4) // FIPS PUB 197, Section 4.2.1, pg 12
}

func Test_aes_mulMod(t *testing.T) {
	var mul byte

	mul = mulMod(0x57, 0x83)
	actual := fmt.Sprintf("%02x", mul)
	assertEqualsString(t, "c1", actual) // FIPS PUB 197, Section 4.2, pg 11

	mul = mulMod(0x57, 0x13)
	actual = fmt.Sprintf("%02x", mul)
	assertEqualsString(t, "fe", actual) // FIPS PUB 197, Section 4.2.1, pg 11

}

func Test_aes_subBytes(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x19, 0xa0, 0x9a, 0xe9}, {0x3d, 0xf4, 0xc6, 0xf8}, {0xe3, 0xe2, 0x8d, 0x48}, {0xbe, 0x2b, 0x2a, 0x08}}
	instance.subBytes()
	actual := fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e 27bfb441 11985d52 aef1e530]", actual) // FIPS PUB 197, Appendix B, pg 33, round=1
}

// Confirm that the tables are fully invertible via round trip substitution
func Test_aes_roundTrips(t *testing.T) {
	for row := 0; row < 16; row++ {
		for col := 0; col < 16; col++ {
			var orig, subSub byte
			sub := sBox[row][col]
			subRow := sub >> 4
			subCol := sub & 0x0f
			subSub = invSBox[subRow][subCol]
			orig = uint8(row<<4 + col)
			actual := fmt.Sprintf("%v", orig == subSub)
			assertEqualsString(t, "true", actual) // FIPS PUB 197, Section 5.1.1 and 5.3.2, Fig 7 and 14, pg 16,22
		}
	}
}

func Test_aes_shiftRows(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0x27, 0xbf, 0xb4, 0x41}, {0x11, 0x98, 0x5d, 0x52}, {0xae, 0xf1, 0xe5, 0x30}}
	instance.shiftRows()
	actual := fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e bfb44127 5d521198 30aef1e5]", actual) // FIPS PUB 197, Appendix B, pg 33, round=1
}

func Test_aes_mixColumns(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0xbf, 0xb4, 0x41, 0x27}, {0x5d, 0x52, 0x11, 0x98}, {0x30, 0xae, 0xf1, 0xe5}}
	instance.mixColumns()
	actual := fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[04e04828 66cbf806 8119d326 e59a7a4c]", actual) // FIPS PUB 197, Appendix B, pg 33, round=1
}

func Test_aes_addRoundKey(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x04, 0xe0, 0x48, 0x28}, {0x66, 0xcb, 0xf8, 0x06}, {0x81, 0x19, 0xd3, 0x26}, {0xe5, 0x9a, 0x7a, 0x4c}}
	instance.expandedAesKey[4], instance.expandedAesKey[5], instance.expandedAesKey[6], instance.expandedAesKey[7] = 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605
	instance.addRoundKey(1)
	actual := fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[a4686b02 9c9f5b6a 7f35ea50 f22b4349]", actual) // FIPS PUB 197, Appendix B, pg 33, round=2
}

//
// AES cipher; Note that decrypt functionality isn't actually needed for GCM
//

func Test_aes_encrypt_128(t *testing.T) {
	var cText []byte
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	instance := new(aesgcm).expandAesKey(key)
	pText, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	cText = instance.encrypt(pText)
	actual := fmt.Sprintf("%032x", cText)
	assertEqualsString(t, "69c4e0d86a7b0430d8cdb78070b4c55a", actual) // FIPS PUB 197, Appendix C.1, pg 35-36
}

func Test_aes_encrypt_192(t *testing.T) {
	var cText []byte
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f1011121314151617")
	instance := new(aesgcm).expandAesKey(key)
	pText, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	cText = instance.encrypt(pText)
	actual := fmt.Sprintf("%032x", cText)
	assertEqualsString(t, "dda97ca4864cdfe06eaf70a0ec0d7191", actual) // FIPS PUB 197, Appendix C.2, pg 38-40
}

func Test_aes_encrypt_256(t *testing.T) {
	var cText []byte
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	instance := new(aesgcm).expandAesKey(key)
	pText, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	cText = instance.encrypt(pText)
	actual := fmt.Sprintf("%032x", cText)
	assertEqualsString(t, "8ea2b7ca516745bfeafc49904b496089", actual) // FIPS PUB 197, Appendix C.3, pg 42-43
}

//
// GCM internals
//

func Test_gcm_keyExpansion_256(t *testing.T) {
	var instance cipher.AEAD
	key, _ := hex.DecodeString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	instance = NewAESGCM(key)
	actual := fmt.Sprintf("%08x", instance.(*aesgcm).expandedAesKey[59])
	assertEqualsString(t, "706c631e", actual) // FIPS PUB 197, Appendix A.3, pg 30,32
}

func Test_gcm_initH(t *testing.T) {
	var instance cipher.AEAD
	key, _ := hex.DecodeString("00000000000000000000000000000000")
	instance = NewAESGCM(key)
	pText, _ := hex.DecodeString("00000000000000000000000000000000")
	instance.(*aesgcm).initGcmH(pText)
	actual := fmt.Sprintf("%016x", instance.(*aesgcm).h)
	assertEqualsString(t, "{66e94bd4ef8a2c3b 884cfa59ca342b2e}", actual) // GCM Operation, Appendix B, Test Case 1, pg 27
}

func Test_gcm_initializeH(t *testing.T) {
	var instance cipher.AEAD
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	instance = NewAESGCM(key)
	actual := fmt.Sprintf("%016x", instance.(*aesgcm).h)
	assertEqualsString(t, "{b83b533708bf535d 0aa6e52980d53b78}", actual) // GCM Operation, Appendix B, Test Case 3, pg 28
}

func Test_gcm_xMulY_1(t *testing.T) {
	H := blockWord{0xb83b533708bf535d, 0x0aa6e52980d53b78}
	A1 := blockWord{0, 0} // H to be multiplied by 0
	var X1 blockWord
	X1 = bwXMulY(A1, H)
	actual := fmt.Sprintf("%016x", X1)
	assertEqualsString(t, "{0000000000000000 0000000000000000}", actual) // First principles
}

func Test_gcm_xMulY_2(t *testing.T) {
	H := blockWord{0xb83b533708bf535d, 0x0aa6e52980d53b78}
	A1 := blockWord{0xfeedfacedeadbeef, 0xfeedfacedeadbeef} // First full block of A
	var X1 blockWord
	X1 = bwXMulY(A1, H)
	actual := fmt.Sprintf("%016x", X1)
	assertEqualsString(t, "{ed56aaf8a72d6704 9fdb9228edba1322}", actual) // GCM operation, Appendix B, Test Case 4, pg 29
}

func Test_gcm_xMulY_3(t *testing.T) {
	H := blockWord{0xb83b533708bf535d, 0x0aa6e52980d53b78}
	C1 := blockWord{0x42831ec221777424, 0x4b7221b784d0d49c} // First block of C
	var X1 blockWord
	X1 = bwXMulY(C1, H)
	actual := fmt.Sprintf("%016x", X1)
	assertEqualsString(t, "{59ed3f2bb1a0aaa0 7c9f56c6a504647b}", actual) // GCM operation, Appendix B, Test Case 3, pg 28
}

func Test_gcm_xMulY_commutative(t *testing.T) {
	// Multiplication should be commutative ->  A*B == B*A
	for index := 0; index < 10000; index++ { // 10k iterations
		operandA := blockWord{rand.Uint64(), rand.Uint64()}
		operandB := blockWord{rand.Uint64(), rand.Uint64()}
		result1 := bwXMulY(operandA, operandB)
		result2 := bwXMulY(operandB, operandA)
		assertEqualsString(t, fmt.Sprintf("%016x", result1.left), fmt.Sprintf("%016x", result2.left))   // First principles
		assertEqualsString(t, fmt.Sprintf("%016x", result1.right), fmt.Sprintf("%016x", result2.right)) // First principles
	}
}

func Test_gcm_xMulY_associative(t *testing.T) {
	// Multiplication should be commutative ->  (A*B)*C == A*(B*C)
	for index := 0; index < 10000; index++ { // 10k iterations
		operandA := blockWord{rand.Uint64(), rand.Uint64()}
		operandB := blockWord{rand.Uint64(), rand.Uint64()}
		operandC := blockWord{rand.Uint64(), rand.Uint64()}
		result1 := bwXMulY(bwXMulY(operandA, operandB), operandC)
		result2 := bwXMulY(operandA, bwXMulY(operandB, operandC))
		assertEqualsString(t, fmt.Sprintf("%016x", result1.left), fmt.Sprintf("%016x", result2.left))   // First principles
		assertEqualsString(t, fmt.Sprintf("%016x", result1.right), fmt.Sprintf("%016x", result2.right)) // First principles
	}
}

func Test_gcm_xMulY_distributive(t *testing.T) {
	// Multiplication should be commutative ->  (A+B)*C == A*C+B*C
	for index := 0; index < 10000; index++ { // 10k iterations
		operandA := blockWord{rand.Uint64(), rand.Uint64()}
		operandB := blockWord{rand.Uint64(), rand.Uint64()}
		operandC := blockWord{rand.Uint64(), rand.Uint64()}
		result1 := bwXMulY(bwXor(operandA, operandB), operandC)
		result2 := bwXor(bwXMulY(operandA, operandC), bwXMulY(operandB, operandC))
		assertEqualsString(t, fmt.Sprintf("%016x", result1.left), fmt.Sprintf("%016x", result2.left))   // First principles
		assertEqualsString(t, fmt.Sprintf("%016x", result1.right), fmt.Sprintf("%016x", result2.right)) // First principles
	}
}

func Test_gcm_incM32(t *testing.T) {
	var incResult blockWord

	incResult = plusM32(blockWord{0xFEDCBA9876543210, 0xFEDCBA9876543210}, 1)
	actual := fmt.Sprintf("%016x", incResult)
	assertEqualsString(t, "{fedcba9876543210 fedcba9876543211}", actual) // Contrived data

	incResult = plusM32(blockWord{0xFEDCBA9876543210, 0xFEDCBA98EFFFFFFF}, 1)
	actual = fmt.Sprintf("%016x", incResult)
	assertEqualsString(t, "{fedcba9876543210 fedcba98f0000000}", actual) // Contrived data

	incResult = plusM32(blockWord{0xFEDCBA9876543210, 0xFEDCBA98FFFFFFFF}, 1)
	actual = fmt.Sprintf("%016x", incResult)
	assertEqualsString(t, "{fedcba9876543210 fedcba9800000000}", actual) // Contrived data

	incResult = plusM32(blockWord{0xcafebabefacedbad, 0xdecaf88800000003}, 1)
	actual = fmt.Sprintf("%016x", incResult)
	assertEqualsString(t, "{cafebabefacedbad decaf88800000004}", actual) // GCM operation, Appendix B, Test Case 3, pg 28
}
