package aesgcm_test

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"testing"
)

var testFiles = []string{
	"./gcmtestvectors/gcmEncryptExtIV128.rsp",
	"./gcmtestvectors/gcmEncryptExtIV192.rsp",
	"./gcmtestvectors/gcmEncryptExtIV256.rsp",
	//"./gcmtestvectors/gcmDecrypt128.rsp",
	//"./gcmtestvectors/gcmDecrypt192.rsp",
	//"./gcmtestvectors/gcmDecrypt256.rsp",
}

func TestMain(m *testing.M) {
	var problem bool
	for _, fileName := range testFiles {
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
	os.Exit(m.Run())
}

func Test_gcmEncryptExtIV128(t *testing.T) {

	for _, fileName := range testFiles {
		var Keylen, IVlen, PTlen, AADlen, Taglen, Count, n int
		var Key, IV, PT, AAD, CT, Tag []byte
		var problem bool
		var lineNumber int

		fileHandle, err := os.Open(fileName)
		if err != nil {
			os.Exit(123)
		}

		fileScanner := bufio.NewScanner(fileHandle)
		for fileScanner.Scan() {
			line := fileScanner.Text()
			n, _ = fmt.Sscanf(line, "[Keylen = %d]", &Keylen)
			n, _ = fmt.Sscanf(line, "[IVlen = %d]", &IVlen)
			n, _ = fmt.Sscanf(line, "[PTlen = %d]", &PTlen)
			n, _ = fmt.Sscanf(line, "[AADlen = %d]", &AADlen)
			n, _ = fmt.Sscanf(line, "[Taglen = %d]", &Taglen)
			n, _ = fmt.Sscanf(line, "Count = %d", &Count)
			n, _ = fmt.Sscanf(line, "Key = %x", &Key)
			if n > 0 {
				problem = problem || len(Key) != Keylen/8
			}
			n, _ = fmt.Sscanf(line, "IV = %x", &IV)
			n, _ = fmt.Sscanf(line, "PT = %x", &PT)
			n, _ = fmt.Sscanf(line, "AAD = %x", &AAD)
			n, _ = fmt.Sscanf(line, "CT = %x", &CT)
			n, _ = fmt.Sscanf(line, "Tag = %x", &Tag)
			lineNumber++
			if n > 0 {
				if IVlen != 96 {
					continue
				}
				//fmt.Printf("PTlen=%v len(PT)=%v", PTlen, len(PT))
				t.Run("first", testSeal(IV, Key, PT[0:PTlen/8], AAD[0:AADlen/8], CT[0:PTlen/8], Tag, lineNumber))

				//os.Exit(2)
			}

		}

		fileHandle.Close()

		fmt.Println("lets test a file")
	}

}

func testSeal(nonce, key, plaintext, additionalData, ciphertext, tag []byte, lineNumber int) func(*testing.T) {
	return func(t *testing.T) {

		block, _ := aes.NewCipher(key)
		aesgcm, _ := cipher.NewGCM(block)
		actual := aesgcm.Seal(nil, nonce, plaintext, additionalData)
		expected := ciphertext
		if len(ciphertext) > 0 && !bytes.Equal(expected, actual) {
			t.Error(fmt.Sprintf("Expected %x, got %x on line %d", expected, actual, lineNumber))
		}
	}
}
