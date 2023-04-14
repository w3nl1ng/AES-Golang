package main

import (
    myaes "cryptoproj/mycrypto/aes"
    "fmt"
)

func main() {
    palin := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',00, 11, 22, 33, 44, 55, 66, 77, 88, 99, 1, 2, 3, 4, 5, 6}
    key := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

    out := myaes.Encrypto(palin, key)
    fmt.Println(out)
}