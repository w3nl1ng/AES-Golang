package aes

import (
	"reflect"
	"testing"
)

func TestDecrypto128(t *testing.T) {
	key := "0123456789abcdef"
	plaintext := "hello, this is the plaintext!!!!"

	cipher := standLibraryAESEncrypto([]byte(plaintext), []byte(key))
	decryptoText := Decrypto([]byte(cipher), []byte(key))

	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatal("my AES decrypto return a wrong answer")
	}
}


func TestDecrypto192(t *testing.T) {
	key := "0123456789abcdefghijklmn"
	plaintext := "hello, this is the plaintext!!!!"

	cipher := standLibraryAESEncrypto([]byte(plaintext), []byte(key))
	decryptoText := Decrypto([]byte(cipher), []byte(key))

	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatal("my AES decrypto return a wrong answer")
	}
}

func TestDecrypto256(t *testing.T) {
	key := "0123456789abcdefghijklmnopqrstuv"
	plaintext := "hello, this is the plaintext!!!!"

	cipher := standLibraryAESEncrypto([]byte(plaintext), []byte(key))
	decryptoText := Decrypto([]byte(cipher), []byte(key))

	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatal("my AES decrypto return a wrong answer")
	}
}