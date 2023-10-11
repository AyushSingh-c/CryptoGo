package cryptoES

import (
	"crypto/des"
	"fmt"
	"strconv"
)

func EncryptECB_DES(key []byte, text []byte) []byte {
	plaintext := text
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted := make([]byte, len(plaintext))
	bs := block.BlockSize()
	ent := encrypted
	for len(plaintext) > 0 {
		block.Encrypt(ent, plaintext[:bs])
		plaintext = plaintext[bs:]
		ent = ent[bs:]
	}
	return encrypted
}

func DecryptECB_DES(key []byte, text []byte) []byte {
	ciphertext := text
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	decrypted := make([]byte, len(ciphertext))
	bs := block.BlockSize()
	dst := decrypted
	for len(ciphertext) > 0 {
		block.Decrypt(dst, ciphertext[:bs])
		ciphertext = ciphertext[bs:]
		dst = dst[bs:]
	}
	return decrypted
}

func Solve2DES(samplePlaintext []byte, sampleCiphertext []byte, flagEnc []byte, listKey []string) {
	// Create an empty slice of strings
	listEncrypted := []string{}
	listDecrypted := []string{}

	// Loop from 0 to 999999
	for i := 0; i <= 999999; i++ {
		s := strconv.Itoa(i)
		s = fmt.Sprintf("%06s", s)
		key := []byte(s + "  ")
		listKey = append(listKey, string(key))

		// Encrypt the plaintext using the block
		ciphertext := EncryptECB_DES(key, []byte(samplePlaintext))
		listEncrypted = append(listEncrypted, string(ciphertext))

		// Decrypt the ciphertext using the block
		decrypted := DecryptECB_DES(key, sampleCiphertext)
		listDecrypted = append(listDecrypted, string(decrypted))
	}

	// Finding Keys of 2DES
	indexMap := make(map[string]int)

	// Loop over the first list and store the indexes in the map
	for i, s := range listEncrypted {
		indexMap[s] = i
	}

	for j, s := range listDecrypted {
		i, ok := indexMap[s]
		if ok {
			KEY1 := listKey[i]
			KEY2 := listKey[j]

			// Finding Flag
			flag := DecryptECB_DES([]byte(KEY1), DecryptECB_DES([]byte(KEY2), flagEnc))
			// fmt.Println("Possible KEYS: ", KEY1, KEY2)
			fmt.Println("Possible Flag: ", string(flag))
		}
	}
}
