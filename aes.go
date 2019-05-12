package aesgcm

// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

import (
	"encoding/binary"
)

func (aesgcm *aesgcm) expandAesKey(key []byte) *aesgcm {
	var nk = len(key) / 4
	rcon := [11]uint32{0, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000}
	aesgcm.nr = nk + 6

	for index := 0; index < nk; index++ {
		aesgcm.expandedAesKey[index] = uint32(key[index*4])<<24 | uint32(key[index*4+1])<<16 |
			uint32(key[index*4+2])<<8 | uint32(key[index*4+3])
	}

	for index := nk; index < (aesgcm.nr+1)*4; index++ {
		temp := aesgcm.expandedAesKey[index-1]
		if index%nk == 0 {
			rw := rotWord(temp)
			sw := subWord(rw)
			var rc = rcon[index/nk]
			temp = sw ^ rc
		} else if nk > 6 && index%nk == 4 {
			temp = subWord(temp)
		}
		aesgcm.expandedAesKey[index] = aesgcm.expandedAesKey[index-nk] ^ temp
	}
	return aesgcm
}

func rotWord(word uint32) uint32 { // expandAesKey expansion
	var bytes1 = make([]byte, 4)
	binary.BigEndian.PutUint32(bytes1, word) // byte0->MSB
	var bytes2 = make([]byte, 4)
	copy(bytes2[0:3], bytes1[1:4])
	bytes2[3] = bytes1[0]
	var x = binary.BigEndian.Uint32(bytes2)
	return x
}

func subWord(word uint32) uint32 { // expandAesKey expansion
	var bytes = make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, word) // byte0->MSB
	for i := 0; i < 4; i++ {
		var row = bytes[i] >> 4
		var col = bytes[i] & 0x0f
		bytes[i] = sBox[row][col]
	}
	var x = binary.BigEndian.Uint32(bytes)
	return x
}

func (aesgcm *aesgcm) encrypt(message []byte) []byte {
	if len(message) == 64 {
		panic("Encryption currently only works for a single block")
	}
	var cipherText = make([]byte, 16)

	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			aesgcm.state[row][col] = message[col*4+row]
		}
	}
	aesgcm.addRoundKey(0)
	for round := 1; round < aesgcm.nr+1; round++ {
		aesgcm.subBytes()
		aesgcm.shiftRows()
		if round != aesgcm.nr {
			aesgcm.mixColumns()
		}
		aesgcm.addRoundKey(round)
	}

	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			cipherText[col*4+row] = aesgcm.state[row][col]
		}
	}
	return cipherText
}

func (aesgcm *aesgcm) addRoundKey(round int) {
	for col := 0; col < 4; col++ {
		var colWord uint32
		colWord = uint32(aesgcm.state[0][col])<<24 + uint32(aesgcm.state[1][col])<<16 + uint32(aesgcm.state[2][col])<<8 + uint32(aesgcm.state[3][col])
		colWord = colWord ^ aesgcm.expandedAesKey[(round*4)+col]
		aesgcm.state[0][col] = byte(colWord >> 24)
		aesgcm.state[1][col] = byte(colWord >> 16)
		aesgcm.state[2][col] = byte(colWord >> 8)
		aesgcm.state[3][col] = byte(colWord)
	}
}

func (aesgcm *aesgcm) subBytes() { // Round cipher
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			var itemRow = aesgcm.state[row][col] >> 4
			var itemCol = aesgcm.state[row][col] & 0x0f
			aesgcm.state[row][col] = sBox[itemRow][itemCol]
		}
	}
}

func (aesgcm *aesgcm) shiftRows() {
	var newState = [4][4]byte{}
	copy(newState[0][0:4], aesgcm.state[0][0:4]) // Row 0 is unchanged

	copy(newState[1][0:3], aesgcm.state[1][1:4]) // Row 1
	copy(newState[1][3:4], aesgcm.state[1][0:1]) // Row 1

	copy(newState[2][0:2], aesgcm.state[2][2:4]) // Row 2
	copy(newState[2][2:4], aesgcm.state[2][0:2]) // Row 2

	copy(newState[3][0:1], aesgcm.state[3][3:4]) // Row 3
	copy(newState[3][1:4], aesgcm.state[3][0:3]) // Row 3

	aesgcm.state = newState
}

func (aesgcm *aesgcm) mixColumns() {
	var newState = [4][4]byte{}

	for col := 0; col < 4; col++ {
		newState[0][col] = mulMod(0x02, aesgcm.state[0][col]) ^ mulMod(0x03, aesgcm.state[1][col]) ^ aesgcm.state[2][col] ^ aesgcm.state[3][col]
		newState[1][col] = aesgcm.state[0][col] ^ mulMod(0x02, aesgcm.state[1][col]) ^ mulMod(0x03, aesgcm.state[2][col]) ^ aesgcm.state[3][col]
		newState[2][col] = aesgcm.state[0][col] ^ aesgcm.state[1][col] ^ mulMod(0x02, aesgcm.state[2][col]) ^ mulMod(0x03, aesgcm.state[3][col])
		newState[3][col] = mulMod(0x03, aesgcm.state[0][col]) ^ aesgcm.state[1][col] ^ aesgcm.state[2][col] ^ mulMod(0x02, aesgcm.state[3][col])
	}
	aesgcm.state = newState
}

func mulMod(x, y byte) byte {
	var result uint
	var runningXt byte
	runningXt = x
	for i := uint(0); i < 8; i++ {
		if y&(1<<i) != 0x00 {
			result = result ^ uint(runningXt)
		}
		runningXt = xtime(runningXt)
	}
	return byte(result)
}

func xtime(x byte) byte {
	var result uint
	result = uint(x) << 1
	if x&(1<<7) != 0 {
		result = result ^ 0x1b
	}
	return byte(result)
}
