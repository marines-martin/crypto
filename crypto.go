package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	mylog "jupiter.com/log"
)

// Encrypt encrypt string using a given key
func Encrypt(keyString64 string, stringToEncrypt string) (string, error) {

	var out string

	var function = "Encrypt"

	key, _ := hex.DecodeString(keyString64)

	plaintext := []byte(stringToEncrypt)
	block, err := aes.NewCipher(key)
	if err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	dst := make([]byte, hex.EncodedLen(len(ciphertext)))
	hex.Encode(dst, ciphertext)
	out = fmt.Sprintf("%s", dst)

	mylog.ToLog("INFO", "Encrypted:: "+out, function)

	return out, nil

}

// Decrypt decrypt string using the given key
func Decrypt(keyString64 string, encryptedString string) (string, error) {
	var out string
	var function = "Decrypt"
	key, _ := hex.DecodeString(keyString64)
	enc, _ := hex.DecodeString(encryptedString)
	block, err := aes.NewCipher(key)
	if err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		mylog.ToLog("ERROR", "Message:: "+err.Error(), function)
		return out, err
	}
	out = fmt.Sprintf("%s", plaintext)

	mylog.ToLog("INFO", out, function)

	return out, nil
}
