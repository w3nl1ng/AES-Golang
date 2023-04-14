package util

import (
	"reflect"
	"testing"
	myaes "cryptoproj/mycrypto/aes"
)

func TestPKCS7Padding1(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6}
	except := []byte{1, 2, 3, 4, 5, 6, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,}

	PKCS7Padding(&data, 16)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7Padding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}

func TestPKCS7Padding2(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,}
	except := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,}

	PKCS7Padding(&data, 16)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7Padding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}


func TestPKCS7Padding3(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3}
	except := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					 0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,}

	PKCS7Padding(&data, 16)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7Padding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}


func TestPKCS7UnPadding1(t *testing.T) {
	except := []byte{1, 2, 3, 4, 5, 6}
	data := []byte{1, 2, 3, 4, 5, 6, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,}

	PKCS7UnPadding(&data)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7UnPadding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}


func TestPKCS7UnPadding2(t *testing.T) {
	except := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,}
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,}

	PKCS7UnPadding(&data)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7UnPadding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}


func TestPKCS7UnPadding3(t *testing.T) {
	except := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 1, 2, 3}
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
					 0, 1, 2, 3, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,}

	PKCS7UnPadding(&data)
	if !reflect.DeepEqual(data, except) {
		t.Fatalf("[PKCS7UnPadding failed]\n[result]: %v\n[except]: %v\n", data, except)
	}
}



func TestPaddingAndAES1(t *testing.T) {
	plaintext := "length20abcdfgjshdfr"
	key := "0123456789abcdef"

	plaintextInByte := []byte(plaintext)
	PKCS7Padding(&plaintextInByte, 16)

	cipher := myaes.Encrypto(plaintextInByte, []byte(key))
	decryptoText := myaes.Decrypto(cipher, []byte(key))

	PKCS7UnPadding(&decryptoText)
	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatalf("[test padding and AES failde]\n[result]: %v\n[except]: %v\n",
					decryptoText, plaintextInByte)
	}
}


func TestPaddingAndAES2(t *testing.T) {
	plaintext := "length10ab"
	key := "0123456789abcdef"

	plaintextInByte := []byte(plaintext)
	PKCS7Padding(&plaintextInByte, 16)

	cipher := myaes.Encrypto(plaintextInByte, []byte(key))
	decryptoText := myaes.Decrypto(cipher, []byte(key))

	PKCS7UnPadding(&decryptoText)
	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatalf("[test padding and AES failde]\n[result]: %v\n[except]: %v\n",
					decryptoText, plaintextInByte)
	}
}


func TestPaddingAndAES3(t *testing.T) {
	plaintext := "length32abamzxnfhujldjfokrjhernl"
	key := "0123456789abcdef"

	plaintextInByte := []byte(plaintext)
	PKCS7Padding(&plaintextInByte, 16)

	cipher := myaes.Encrypto(plaintextInByte, []byte(key))
	decryptoText := myaes.Decrypto(cipher, []byte(key))

	PKCS7UnPadding(&decryptoText)
	if !reflect.DeepEqual(decryptoText, []byte(plaintext)) {
		t.Fatalf("[test padding and AES failde]\n[result]: %v\n[except]: %v\n",
					decryptoText, plaintextInByte)
	}
}