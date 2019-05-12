package aesgcm_test

// Unit tests for aesgcm

// See "FIPS PUB 197" at https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// See "NIST SP800-38D" at https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// See "GCM Operation" at http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

import (
	"aesgcm"
	"bytes"
	"crypto/aes"
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

//Test encryption of exactly single block - test case 3
func Test_aesgcm_Seal_1block(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a")
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%0x", cText[0:len(plaintext)]) // Partial test case, tag not considered here
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49c", actual)
}

//func Test_XXXaesgcm_Seal_1block(t *testing.T) {
//	var additionalData []byte // Not used, empty allocations (var is needed)
//	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
//	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
//	message, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a")
//	instance := aesgcm.New(key)
//	instance.SetIV(nonce)
//	_, _, _ = instance.Encrypt(additionalData, message)
//	actual := fmt.Sprintf("%0x", message) // Partial test case, tag not considered here
//	assertEqualsString(t, "42831ec2217774244b7221b784d0d49c", actual)
//}

//Test encryption of exactly two blocks - test case 3
func Test_aesgcm_Seal_2blocks(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72")
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%0x", cText[0:len(plaintext)]) // Partial test case, tag not considered here
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e", actual)
}

//Test encryption of exactly four blocks - test case 3
func Test_aesgcm_Seal_4blocks(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	actual := fmt.Sprintf("%x", cText)
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"+"4d5c2af327cd64a62cf35abd2ba6fab4", actual)
}

//Test encryption of exactly four blocks - test case 3
//func Test_XXXaesgcm_Seal_4blocks(t *testing.T) {
//	var additionalData []byte // Not used, empty allocations (var is needed)
//	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
//	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
//	message, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
//	instance := aesgcm.New(key)
//	instance.SetIV(nonce)
//	_, tag, _ := instance.Encrypt(additionalData, message)
//	actual := fmt.Sprintf("%x%x", message, tag)
//	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4", actual)
//}

//Test encryption of three blocks plus a fraction - derived from test case 3
func Test_aesgcm_Seal_3blocks_fraction(t *testing.T) {
	var dst, additionalData []byte // Not used, empty allocations (var is needed)
	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
	plaintext, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
	instance := aesgcm.NewAESGCM(key)
	var cText []byte
	cText = instance.Seal(dst, nonce, plaintext, additionalData)
	var actual = fmt.Sprintf("%x", cText[0:len(plaintext)]) // Partial test case, tag not considered here
	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", actual)
}

//Test encryption of three blocks plus a fraction - derived from test case 3
//func Test_XXXaesgcm_Seal_3blocks_fraction(t *testing.T) {
//	var additionalData []byte // Not used, empty allocations (var is needed)
//	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308")
//	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
//	message, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
//	instance := aesgcm.New(key)
//	instance.SetIV(nonce)
//	_, _, _ = instance.Encrypt(additionalData, message)
//	var actual = fmt.Sprintf("%x", message) // Partial test case, tag not considered here
//	assertEqualsString(t, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", actual)
//}

//Test encryption of three blocks plus a fraction - derived from test case 10
//func Test_testcase11(t *testing.T) {
//	additionalData, _ := hex.DecodeString("feedfacedeadbeeffeedfacedeadbeefabaddad2")
//	key, _ := hex.DecodeString("feffe9928665731c6d6a8f9467308308feffe9928665731c")
//	nonce, _ := hex.DecodeString("cafebabefacedbaddecaf888")
//	message, _ := hex.DecodeString("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
//	instance := aesgcm.New(key)
//	instance.SetIV(nonce)
//	_, tag, _ := instance.Encrypt(additionalData, message)
//	var actual = fmt.Sprintf("%x-%x", message, tag) // Partial test case, tag not considered here
//	assertEqualsString(t, "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710-2519498e80f1478f37ba55bd6d27618c", actual)
//}

//func aTest_xxxFuz(t *testing.T) {
//	var additionalData []byte
//	for iterations := 0; iterations < 500; iterations++ {
//		var length1 = rand.Intn(2000)  // YAY - Partials work!!!!!!!!!!!
//		var message = make([]byte, length1)
//		rand.Read(message)
//		var keyType = rand.Intn(3)
//		var key = make([]byte, 16+8*keyType)
//		rand.Read(key)
//		var nonce = make([]byte, 12)
//		rand.Read(nonce)
//		var aesBlock1, _ = aes.NewCipher(key)
//		var golang1, _ = cipher.NewGCM(aesBlock1)
//
//		var goCipherText = golang1.Seal([]byte{}, nonce, message, additionalData)
//		goCipherText = goCipherText[0 : len(goCipherText)-16]
//
//		instance := aesgcm.New(key)
//		instance.SetIV(nonce)
//		_, _, _ = instance.Encrypt(additionalData, message)
//
//		if !bytes.Equal(goCipherText, message) {
//			t.Error(fmt.Sprintf("Encrypt fail\nExpected   %v\nActual --> %v\n", goCipherText, message))
//		}
//
//	}
//}

func Test_fuzz_Encrypt_Decrypt(t *testing.T) {
	for iterations := 0; iterations < 5; iterations++ {

		var length1 = rand.Intn(4000)
		var message = make([]byte, length1)
		rand.Read(message)

		var length2 = rand.Intn(4000)
		var additionalData = make([]byte, length2)
		rand.Read(message)

		var keyType = rand.Intn(3)
		var key = make([]byte, 16+8*keyType)
		rand.Read(key)

		var nonce = make([]byte, 12)
		rand.Read(nonce)

		// Encrypt and test
		var aesBlock1, _ = aes.NewCipher(key)
		var golang1, _ = cipher.NewGCM(aesBlock1)

		var goCipherText = golang1.Seal([]byte{}, nonce, message, additionalData)

		var testInstance1 = aesgcm.NewAESGCM(key)
		var ciphertext = testInstance1.Seal([]byte{}, nonce, message, additionalData)

		if !bytes.Equal(goCipherText, ciphertext) {
			t.Error(fmt.Sprintf("Encrypt fail\nExpected   %v\nActual --> %v\n", goCipherText, ciphertext))
		}

		// ecrypt and test

		var aesBlock2, _ = aes.NewCipher(key)
		var golang2, _ = cipher.NewGCM(aesBlock2)

		var goPlainText, err1 = golang2.Open([]byte{}, nonce, ciphertext, additionalData)

		var testInstance2 = aesgcm.NewAESGCM(key)
		var plaintext, err2 = testInstance2.Open([]byte{}, nonce, ciphertext, additionalData)

		if !bytes.Equal(goPlainText, plaintext) {
			t.Error(fmt.Sprintf("Decrypt fail\nExpected   %v\nActual --> %v\n", goPlainText, plaintext))
		}

		if err1 != err2 {
			t.Error(fmt.Sprintf("FAIL fail\nExpected   %v\nActual --> %v\n", err1, err2))

		}

	}
}
