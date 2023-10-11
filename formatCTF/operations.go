package formatCTF

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

func XorHexStrings(hexStrings []string) (string, error) {
	// check if the list is empty
	if len(hexStrings) == 0 {
		return "", fmt.Errorf("empty list")
	}

	// find the minimum length of the hex strings
	minLength := len(hexStrings[0])
	for _, h := range hexStrings {
		if len(h) < minLength {
			minLength = len(h)
		}
	}

	// convert each hex string to bytes and truncate to the minimum length
	byteSlices := make([][]byte, len(hexStrings))
	for i, h := range hexStrings {
		b, err := hex.DecodeString(h)
		if err != nil {
			return "", err
		}
		// truncate the bytes to match the minLength
		b = b[:minLength/2]
		byteSlices[i] = b
	}

	// perform XOR on each pair of bytes
	result := make([]byte, minLength/2)
	for i := 0; i < minLength/2; i++ {
		for _, b := range byteSlices {
			result[i] ^= b[i]
		}
	}

	// convert the result bytes to hex string
	return hex.EncodeToString(result), nil
}

func IsStringPrintable(s string) bool {
	isPrintable := true
	for _, r := range s {
		if !unicode.IsPrint(r) {
			isPrintable = false
			break
		}
	}
	return isPrintable
}

func RunParallel(runFunc func(i int), interations int) {
	var wg sync.WaitGroup        // create a WaitGroup
	for i := 0; i < 10000; i++ { // iterate over a range
		wg.Add(1)        // increment the WaitGroup counter
		go func(i int) { // create a goroutine with an argument
			defer wg.Done() // decrement the WaitGroup counter when done
			runFunc(i)      // call the function and print the result
		}(i) // pass the loop variable as an argument
	}
	wg.Wait()
}

// rotK applies the ROTK cipher to a rune
func rotK(r rune, k int) rune {
	// Check if the rune is a letter and its case
	isLetter, isUpper := letterCase(r)
	if !isLetter {
		return r // Not a letter, do nothing
	}
	ord := 0
	if isUpper {
		ord = int(r - 'A')
	} else {
		ord = int(r - 'a')
	}

	ord = (ord + k) % 26

	if isUpper {
		r = rune(ord + 'A')
	} else {
		r = rune(ord + 'a')
	}

	return r
}

// letterCase checks if a rune is a letter and returns its case
func letterCase(r rune) (bool, bool) {
	isUpper := r >= 'A' && r <= 'Z'
	isLower := r >= 'a' && r <= 'z'
	return isUpper || isLower, isUpper
}

// encrypt encrypts a string using ROT13
func EncryptRot(s string, k int) string {
	rot := func(r rune) rune {
		return rotK(r, k)
	}
	return strings.Map(rot, s)
}

// decrypt decrypts a string using ROT13
func DecryptRot(s string) []string {
	possibleDecrypt := []string{}
	for i := 0; i < 26; i++ {
		rot := func(r rune) rune {
			return rotK(r, i)
		}
		check := strings.Map(rot, s)
		if IsStringPrintable(check) {
			possibleDecrypt = append(possibleDecrypt, check)
		}
	}
	return possibleDecrypt
}
