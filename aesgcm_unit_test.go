package aesgcm_test

// Unit tests for aesgcm

// See "FIPS PUB 197" at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// See "NIST SP800-38D" at https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// See "GCM Operation" at http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

import (
	"aesgcm"
	"fmt"
	"runtime/debug"
	"testing"
)

//
// Testing utils
//

func assertEqualsString(t *testing.T, expected string, actual string) {
	if expected != actual {
		t.Error(fmt.Sprintf("\nExpected %v\nGot  --> %v\n", expected, actual))
		t.Logf(string(debug.Stack()))
	}
}

//Test encryption of exactly single block - test case 3
func Test_aesgcm_Seal_1block(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key := []byte{0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}
	nonce := [3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888}
	plaintext := []byte{0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a}
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%0x", cText)
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49c", actual)
}

//Test encryption of exactly two blocks - test case 3
func Test_aesgcm_Seal_2blocks(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key := []byte{0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}
	nonce := [3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888}
	plaintext := []byte{0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72}
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%0x", cText)
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", actual)
}

//Test encryption of exactly four blocks - test case 3
func Test_aesgcm_Seal_4blocks(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key := []byte{0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}
	nonce := [3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888}
	plaintext := []byte{0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55}
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%x", cText)
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", actual)
}

//Test encryption of three blocks plus a fraction - derived from test case 3
func Test_aesgcm_Seal_3blocks_fraction(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key := []byte{0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08}
	nonce := [3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888}
	plaintext := []byte{0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39}
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	var actual = fmt.Sprintf("%x", cText)
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", actual)
}