package aesgcm

import (
	"fmt"
	"math/rand"
	"runtime/debug"
	"testing"
)

func TestNewAESGCM(t *testing.T) {
	var key = []byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
		0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
		0xa3, 0x09, 0x14, 0xdf, 0xf4}
	var instance = NewAESGCM(key)
	assertEqualsUint32(t, 0x706c631e, instance.eKey[59], "Bad eKey[59]")
}

// Create table tests for H and inc

func Example_eKY0() {
	eKY0()
	// Output: asdf
}

func Test_genICB(t *testing.T) { // Called Y0 in "revised spec testcases"
	genICB([3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888})
	var res = fmt.Sprintf("%x", icb)
	assertEqualsString(t, "{cafebabefacedbad decaf88800000001}", res, "blah")

}

func Test_initH(t *testing.T) {
	initH([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	var res = fmt.Sprintf("%x", H)
	assertEqualsString(t, "{66e94bd4ef8a2c3 884cfa59ca342b2e}", res, "blah")
}

// See https://stackoverflow.com/questions/10655026/gcm-multiplication-implementation
func Test_algorithm1(t *testing.T) {

	//var multTests = []struct {
	//	operandA  bWord
	//	operandB bWord
	//	expectedH string
	//}{
	//	{bWord{0xfedcba9876543210, 0xfedcba9876543210}, bWord{0xfedcba9876543210, 0xfedcba9876543210}, "N/A"},
	//	{bWord{0xfedcba9876543210, 0xfedcba9876543210}, bWord{0xfedcba9876543210, 0xfedcba9876543210}, "N/A"},
	//}

	// Multiplication should be commutative
	for index := 0; index < 100000; index++ {
		operandA := bWord{rand.Uint64(), rand.Uint64()}
		operandB := bWord{rand.Uint64(), rand.Uint64()}
		result1 := xMuly(operandA, operandB)
		result2 := xMuly(operandB, operandA)
		assertEqualsUint64(t, result1.left, result2.left, "left went bad")
		assertEqualsUint64(t, result1.right, result2.right, "right went bad")
	}
}

func Test_incM32(t *testing.T) {
	var result1 = incM32(bWord{0xFEDCBA9876543210, 0xFEDCBA9876543210})
	var r1 = fmt.Sprintf("%x", result1)
	assertEqualsString(t, "{fedcba9876543210 fedcba9876543211}", r1, "hmmm")
	var result2 = incM32(bWord{0xFEDCBA9876543210, 0xFEDCBA98EFFFFFFF})
	var r2 = fmt.Sprintf("%x", result2)
	assertEqualsString(t, "{fedcba9876543210 fedcba98f0000000}", r2, "hmmm")
	var result3 = incM32(bWord{0xFEDCBA9876543210, 0xFEDCBA98FFFFFFFF})
	var r3 = fmt.Sprintf("%x", result3)
	assertEqualsString(t, "{fedcba9876543210 fedcba9800000000}", r3, "hmmm")

}

// TODO
// 1. Annotate data sources (e.g. Appendix X.Y.Z); Revise Example->Test/Check; ----> Hit ~100% test coverage
// 2. Implement trivial benchmark for first data point

//
// Testing utils
//

func assertEqualsUint64(t *testing.T, expected uint64, actual uint64, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v, Got %v --> %v", expected, actual, message))
		//t.Logf(string(debug.Stack()))
	}
}

func assertEqualsUint32(t *testing.T, expected uint32, actual uint32, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

func assertEqualsByte(t *testing.T, expected byte, actual byte, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

func assertEqualsString(t *testing.T, expected string, actual string, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

//
// Key expansion internals; data from Appendix A.1 i=4
//

func Test_rotWord(t *testing.T) {
	var result = rotWord(0x09cf4f3c)
	assertEqualsUint32(t, 0xcf4f3c09, result, "Bad rotWord")
}

func Test_subWord(t *testing.T) {
	var result = subWord(0xcf4f3c09)
	assertEqualsUint32(t, 0x8a84eb01, result, "Bad subWord")
}

//
// Key expansion; data from Appendix A.1, A.2 and A.3
//

func ExampleNew_Key128() {
	var instance = New().Key([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
		0x88, 0x09, 0xcf, 0x4f, 0x3c})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[43])
	// Output: 09cf4f3c - b6630ca6
}

func ExampleNew_Key192() {
	var instance = New().Key([]byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3,
		0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[51])
	// Output: 809079e5 - 01002202
}
func ExampleNew_Key256() {
	var instance = New().Key([]byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
		0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
		0xa3, 0x09, 0x14, 0xdf, 0xf4})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[59])
	// Output: 857d7781 - 706c631e
}

//
// Cipher internals; data from section 4.2, 4.2.1 and Appendix B
//

func Test_xtime(t *testing.T) {
	assertEqualsByte(t, 0xae, xtime(0x57), "Bad xtime(0x57")
	assertEqualsByte(t, 0x47, xtime(0xae), "Bad xtime(0xae)")
	assertEqualsByte(t, 0x8e, xtime(0x47), "Bad xtime(0x47")
	assertEqualsByte(t, 0x07, xtime(0x8e), "Bad xtime(0x8e)")
}

func Test_mulMod(t *testing.T) {
	assertEqualsByte(t, 0xc1, mulMod(0x57, 0x83), "Bad mulMod")
}

func Test_subBytes(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x19, 0xa0, 0x9a, 0xe9}, {0x3d, 0xf4, 0xc6, 0xf8}, {0xe3, 0xe2, 0x8d, 0x48}, {0xbe, 0x2b, 0x2a, 0x08}}
	instance.subBytes()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e 27bfb441 11985d52 aef1e530]", result, "Bad subBytes")
}

func Test_invSubBytes(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0x27, 0xbf, 0xb4, 0x41}, {0x11, 0x98, 0x5d, 0x52}, {0xae, 0xf1, 0xe5, 0x30}}
	instance.invSubBytes()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[19a09ae9 3df4c6f8 e3e28d48 be2b2a08]", result, "Bad invSubBytes")
}

// Confirm that the tables are fully invertible
func TestRoundTrips(t *testing.T) {
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			var x = sBox[row][col]
			var xRow = x >> 4
			var xCol = x & 0x0f
			var y = invSBox[xRow][xCol]
			var z = uint32(row<<4 + col)
			assertEqualsUint32(t, z, uint32(y), fmt.Sprintf("X %02x != %02xy", x, y))
		}
	}
}

func Test_shiftRows(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0x27, 0xbf, 0xb4, 0x41}, {0x11, 0x98, 0x5d, 0x52}, {0xae, 0xf1, 0xe5, 0x30}}
	instance.shiftRows()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e bfb44127 5d521198 30aef1e5]", result, "Bad shiftRows")
}

func Test_invShiftRows(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0xbf, 0xb4, 0x41, 0x27}, {0x5d, 0x52, 0x11, 0x98}, {0x30, 0xae, 0xf1, 0xe5}}
	instance.invShiftRows()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e 27bfb441 11985d52 aef1e530]", result, "Bad invShiftRows")
}

func Test_mixColumns(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0xbf, 0xb4, 0x41, 0x27}, {0x5d, 0x52, 0x11, 0x98}, {0x30, 0xae, 0xf1, 0xe5}}
	instance.mixColumns()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[04e04828 66cbf806 8119d326 e59a7a4c]", result, "Bad mixColumns")
}

func Test_invMixColumns(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x04, 0xe0, 0x48, 0x28}, {0x66, 0xcb, 0xf8, 0x06}, {0x81, 0x19, 0xd3, 0x26}, {0xe5, 0x9a, 0x7a, 0x4c}}
	instance.invMixColumns()
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[d4e0b81e bfb44127 5d521198 30aef1e5]", result, "Bad invMixColumns")
}

func Test_addRoundKey(t *testing.T) {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x04, 0xe0, 0x48, 0x28}, {0x66, 0xcb, 0xf8, 0x06}, {0x81, 0x19, 0xd3, 0x26}, {0xe5, 0x9a, 0x7a, 0x4c}}
	instance.eKey[4], instance.eKey[5], instance.eKey[6], instance.eKey[7] = 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605
	instance.addRoundKey(1)
	var result = fmt.Sprintf("%08x", instance.state)
	assertEqualsString(t, "[a4686b02 9c9f5b6a 7f35ea50 f22b4349]", result, "Bad addRoundKey")
}

//
// Cipher; data from Appendix C.1, C.2, C.3
//

func ExampleAesgcm_Encrypt128() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: 69c4e0d86a7b0430d8cdb78070b4c55a
}

func ExampleAesgcm_Decrypt128() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
	result := instance.Decrypt([]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a})
	fmt.Printf("%x", result)
	// Output: 00112233445566778899aabbccddeeff
}

func ExampleAesgcm_Encrypt192() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: dda97ca4864cdfe06eaf70a0ec0d7191
}

func ExampleAesgcm_Decrypt192() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
	result := instance.Decrypt([]byte{0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91})
	fmt.Printf("%x", result)
	// Output: 00112233445566778899aabbccddeeff
}

func ExampleAesgcm_Encrypt256() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		0x1b, 0x1c, 0x1d, 0x1e, 0x1f})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: 8ea2b7ca516745bfeafc49904b496089
}

func ExampleAesgcm_Decrypt256() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		0x1b, 0x1c, 0x1d, 0x1e, 0x1f})
	result := instance.Decrypt([]byte{0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89})
	fmt.Printf("%x", result)
	// Output: 00112233445566778899aabbccddeeff
}
