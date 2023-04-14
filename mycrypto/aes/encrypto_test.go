package aes

import (
	stdlibaes "crypto/aes"
	"reflect"
	"testing"
)

func standLibraryAESEncrypto(plaintext []byte, key []byte) []byte {
	cipher := make([]byte, 0)
	block, _ := stdlibaes.NewCipher(key)
	blockSize := block.BlockSize()
	cipherBlock := make([]byte, blockSize)

	for i := 0; i < len(plaintext); i += 16 {
		block.Encrypt(cipherBlock, plaintext[i:i+16])
		cipher = append(cipher, cipherBlock...)
	}
	return cipher
}

func TestEncrypto128(t *testing.T) {
	key := "0123456789abcdef"
	plaintext := "hello, this is the plaintext!!!!"

	myAESCipher := Encrypto([]byte(plaintext), []byte(key))
	stdAESCipher := standLibraryAESEncrypto([]byte(plaintext), []byte(key))

	if !reflect.DeepEqual(myAESCipher, stdAESCipher) {
		t.Fatal("my AES encrypto return an wrong cipher")
	}
}