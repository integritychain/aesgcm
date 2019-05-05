package aesgcm_test

import (
	"aesgcm"
	"bufio"
	"bytes"
	"fmt"
	"os"
	"testing"
)

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
			if n > 0 && IVlen == 96 && (PTlen+AADlen) > 1 {
				t.Run(fmt.Sprintf("testEncrypt with  %v  line  %d", fileName, lineNumber),
					testEncrypt(IV, Key, PT[0:PTlen/8], AAD[0:AADlen/8], CT[0:PTlen/8], Tag, Taglen))
			}
		}
		_ = fileHandle.Close()
	}
}

func testEncrypt(nonce, key, plainText, additionalData, cipherText, tag []byte, Taglen int) func(*testing.T) {
	return func(t *testing.T) {
		//block, _ := aes.NewCipher(key)
		//aesgcm, _ := cipher.NewGCM(block)
		var aesgcm = aesgcm.NewAESGCM(key)
		actual := aesgcm.Seal(nil, nonce, plainText, additionalData) // returns cipherText || Tag
		lessTag := len(actual) - 128/8 + Taglen/8
		expected := append(cipherText, tag...)
		if !bytes.Equal(expected, actual[0:lessTag]) {
			t.Error(fmt.Sprintf("\nExpected %x\nGot      %x\n", expected, actual[0:lessTag])) //
		}
	}
}
