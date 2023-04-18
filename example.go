// This a example
package main

import (
	"github.com/w3nl1ng/AES-Golang/mycrypto/aes"
	"github.com/w3nl1ng/AES-Golang/mycrypto/util"
	"fmt"
)

func main() {
	plainText := "If you can't live longer, live deeper."
	key := "0123456789abcdef"

	fmt.Printf("\n[plainText]: %s\n", plainText)

	plaintextInByte := []byte(plainText)
	util.PKCS7Padding(&plaintextInByte, 16)

	cipher := aes.Encrypto(plaintextInByte, []byte(key))
	fmt.Printf("\n[cipher]: %v\n", cipher)

	decryptoText := aes.Decrypto(cipher, []byte(key))
	util.PKCS7UnPadding(&decryptoText)
	fmt.Printf("\n[decryptoText]: %s\n", string(decryptoText))
}