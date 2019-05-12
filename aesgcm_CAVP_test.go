package aesgcm_test

import (
	"aesgcm"
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"strings"
	"testing"
)

var testGolang = false // Set to true to test Go standard package, set to false to test this aesgcm code

var testEncryptFiles = []string{
	"./gcmtestvectors/gcmEncryptExtIV128.rsp", "./gcmtestvectors/gcmEncryptExtIV192.rsp", "./gcmtestvectors/gcmEncryptExtIV256.rsp",
}

var testDecryptFiles = []string{
	"./gcmtestvectors/gcmDecrypt128.rsp", "./gcmtestvectors/gcmDecrypt192.rsp", "./gcmtestvectors/gcmDecrypt256.rsp",
}

func Test_vectorsExist(t *testing.T) {
	var problem bool
	for _, fileName := range append(testEncryptFiles, testDecryptFiles...) {
		_, err := os.Stat(fileName)
		problem = problem || os.IsNotExist(err)
	}
	if problem {
		fmt.Println("Test vector file(s) are not present. Please:")
		fmt.Println(" 1. wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip")
		fmt.Println(" 2. unzip gcmtestvectors.zip -d gcmtestvectors")
		fmt.Println(" 3. rm gcmtestvectors.zip")
		os.Exit(911)
	}
}

func Test_encryption(t *testing.T) {
	var Keylen, IVlen, PTlen, AADlen, Taglen, Count int // CAVP test fields
	var Key, IV, PT, AAD, CT, Tag []byte                // CAVP test fields

	for _, fileName := range testEncryptFiles {
		var lineNumber int

		fileHandle, err := os.Open(fileName)
		if err != nil {
			t.Error(fmt.Sprintf("Unable to open file: %v", fileName))
			return
		}

		fileScanner := bufio.NewScanner(fileHandle)
		for fileScanner.Scan() {
			line := fileScanner.Text()
			lineNumber++
			// Slightly inefficient but effective
			_, _ = fmt.Sscanf(line, "[Keylen = %d]", &Keylen)
			_, _ = fmt.Sscanf(line, "[IVlen = %d]", &IVlen)
			_, _ = fmt.Sscanf(line, "[PTlen = %d]", &PTlen)
			_, _ = fmt.Sscanf(line, "[AADlen = %d]", &AADlen)
			_, _ = fmt.Sscanf(line, "[Taglen = %d]", &Taglen)
			_, _ = fmt.Sscanf(line, "Count = %d", &Count)
			_, _ = fmt.Sscanf(line, "Key = %x", &Key)
			_, _ = fmt.Sscanf(line, "IV = %x", &IV)
			_, _ = fmt.Sscanf(line, "PT = %x", &PT)
			_, _ = fmt.Sscanf(line, "AAD = %x", &AAD)
			_, _ = fmt.Sscanf(line, "CT = %x", &CT)
			n, _ := fmt.Sscanf(line, "Tag = %x", &Tag)
			if n > 0 && IVlen == 96 {
				t.Run(fmt.Sprintf("testEncrypt with  %v  line  %d", fileName, lineNumber),
					testEncrypt(IV, Key, PT[0:PTlen/8], AAD[0:AADlen/8], CT[0:PTlen/8], Tag, Taglen))
			}
		}
		_ = fileHandle.Close()
	}
}

func testEncrypt(nonce, key, plainText, additionalData, cipherText, tag []byte, tagLen int) func(*testing.T) {
	return func(t *testing.T) {
		var aesgcm1 cipher.AEAD
		var dst []byte
		if testGolang {
			block, _ := aes.NewCipher(key)
			aesgcm1, _ = cipher.NewGCM(block)
		} else {
			aesgcm1 = aesgcm.NewAESGCM(key)
		}
		actual := aesgcm1.Seal(dst, nonce, plainText, additionalData) // Actual always gets a 128-bit tag
		expected := append(cipherText, tag...)
		if !bytes.Equal(expected, actual[0:len(actual)+tagLen/8-16]) {
			t.Error(fmt.Sprintf("\nExpected %x\nGot      %x\n", expected, actual)) //
		}
	}
}

func Test_decryption(t *testing.T) {
	var Keylen, IVlen, PTlen, AADlen, Taglen, Count int // CAVP test fields
	var Key, IV, PT, AAD, CT, Tag []byte                // CAVP test fields
	var FAIL bool

	for _, fileName := range testDecryptFiles {
		var lineNumber int

		fileHandle, err := os.Open(fileName)
		if err != nil {
			t.Error(fmt.Sprintf("Unable to open file: %v", fileName))
			return
		}

		fileScanner := bufio.NewScanner(fileHandle)
		for fileScanner.Scan() {
			line := fileScanner.Text()
			lineNumber++
			// Slightly inefficient but effective
			_, _ = fmt.Sscanf(line, "[Keylen = %d]", &Keylen)
			_, _ = fmt.Sscanf(line, "[IVlen = %d]", &IVlen)
			_, _ = fmt.Sscanf(line, "[PTlen = %d]", &PTlen)
			_, _ = fmt.Sscanf(line, "[AADlen = %d]", &AADlen)
			_, _ = fmt.Sscanf(line, "[Taglen = %d]", &Taglen)
			n, _ := fmt.Sscanf(line, "Count = %d", &Count)
			if n > 0 {
				FAIL = false
			} // Reset for new test
			_, _ = fmt.Sscanf(line, "Key = %x", &Key)
			_, _ = fmt.Sscanf(line, "IV = %x", &IV)
			_, _ = fmt.Sscanf(line, "PT = %x", &PT)
			_, _ = fmt.Sscanf(line, "AAD = %x", &AAD)
			_, _ = fmt.Sscanf(line, "CT = %x", &CT)
			_, _ = fmt.Sscanf(line, "Tag = %x", &Tag)
			if strings.Contains(line, "FAIL") {
				FAIL = true
				PT = CT // just so the buffer size works
			}
			if (strings.Contains(line, "FAIL") || strings.Contains(line, "PT =")) && Taglen == 128 && IVlen == 96 {
				t.Run(fmt.Sprintf("testDecrypt with  %v  line  %d", fileName, lineNumber),
					testDecrypt(IV, Key, PT[0:PTlen/8], AAD[0:AADlen/8], CT[0:PTlen/8], Tag[0:Taglen/8], Taglen, FAIL, lineNumber))
			}
		}
		_ = fileHandle.Close()
	}
}

func testDecrypt(nonce, key, plainText, additionalData, cipherText, tag []byte, Taglen int, FAIL bool, lineNumber int) func(*testing.T) {
	return func(t *testing.T) {
		var aesgcm1 cipher.AEAD
		var dst []byte
		if testGolang {
			block, _ := aes.NewCipher(key)
			aesgcm1, _ = cipher.NewGCM(block)
		} else {
			aesgcm1 = aesgcm.NewAESGCM(key)
		}
		if lineNumber == 4429 {
			lineNumber++
		}
		actual, err := aesgcm1.Open(dst, nonce, append(cipherText, tag...), additionalData) // returns plainText
		if err != nil {
			if FAIL {
				return
			} else {
				t.Error(fmt.Sprintf("Open returned error despite no FAIL on line %v\n", lineNumber)) //
			}
		}
		//lessTag := len(actual) - 128/8 + Taglen/8
		expected := plainText // append(cipherText, tag...)
		if !bytes.Equal(expected, actual) {
			t.Error(fmt.Sprintf("\nExpected %x\nGot      %x\n", expected, actual)) //
		}
	}
}
