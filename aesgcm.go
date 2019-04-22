package aesgcm

// See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

import (
	"encoding/binary"
	"log"
)

type aesgcm struct {
	ready bool
	eKey  [60]uint32 // Expanded key
	nk    int        // Number of words in key
	nr    int        // Number of rounds
	state [4][4]byte // State
}

// Key schedule
var w [44]uint32

var state [4][4]byte

var LogFatal = log.Fatalf

// From page 16
var sBox = [16][16]byte{
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
}

func New() *aesgcm {
	return new(aesgcm)
}

func (aesgcm *aesgcm) Key(key []byte) *aesgcm {
	aesgcm.nk = len(key) / 4
	if (aesgcm.nk != 4) && (aesgcm.nk != 6) && (aesgcm.nk != 8) {
		LogFatal("Key length must be 128, 192 or 256 bits")
	}
	rcon := [11]uint32{0, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000}
	aesgcm.nr = [9]int{0, 0, 0, 0, 10, 0, 12, 0, 14}[aesgcm.nk]

	for index := 0; index < aesgcm.nk; index++ {
		aesgcm.eKey[index] = uint32(key[index*4])<<24 | uint32(key[index*4+1])<<16 |
			uint32(key[index*4+2])<<8 | uint32(key[index*4+3])
	}

	for index := aesgcm.nk; index < (aesgcm.nr+1)*4; index++ {
		temp := aesgcm.eKey[index-1]
		if index%aesgcm.nk == 0 {
			rw := rotWord(temp)
			sw := subWord(rw)
			var rc = rcon[index/aesgcm.nk]
			temp = sw ^ rc
		} else if aesgcm.nk > 6 && index%aesgcm.nk == 4 {
			temp = subWord(temp)
		}
		aesgcm.eKey[index] = aesgcm.eKey[index-aesgcm.nk] ^ temp
	}

	aesgcm.ready = true
	return aesgcm
}

func rotWord(word uint32) uint32 { // Key expansion
	var bytes1 = make([]byte, 4)
	binary.BigEndian.PutUint32(bytes1, word) // byte0->MSB
	var bytes2 = make([]byte, 4)
	copy(bytes2[0:3], bytes1[1:4])
	bytes2[3] = bytes1[0]
	var x = binary.BigEndian.Uint32(bytes2)
	return x
}

func subWord(word uint32) uint32 { // Key expansion
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

func (aesgcm *aesgcm) Encrypt(message []byte) []byte {
	if !aesgcm.ready {
		LogFatal("The key must be set prior to encrypting data")
	}
	if len(message) == 64 {
		LogFatal("Encryption currently only works for a single block")
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
		colWord = colWord ^ aesgcm.eKey[(round*4)+col]
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
