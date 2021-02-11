/*
Author: Luis Fueris
Date: September 24, 2020
Description: this sample code shows a function that encrypt/decrypt (please,
erase comments if you want to do cipher operation) an URL dynamically. It 
could be use to hide a C&C URL from static analysis

*/
package main

import (
    "fmt"
)

// URL length
var LEN = 23


// Implements XOR bitwise operation to URL string
//
func encryptUrl(url []string, key []byte) []byte {
    bLetter := make([]byte, 1)
    cipherLetter := make([]byte, 1)
    cipherUrl := make([]byte, LEN)

    for i, letter := range url {
        bLetter = []byte(letter)
        for j, bit := range bLetter {
            cipherLetter[j] = bit ^ key[j]
        }

        cipherUrl[i] = cipherLetter[0]
    }

    return cipherUrl
}

// Main program checks is a debugger is present and calls cipherUrl() function
// in order to decrypt malicious URL. It should be noted that XOR cipher uses
// same function to encrypt and decrypt so if you want to encrypt something, 
// please erase comments (oUrl var) and call encryptUrl() 
//
func main() {

    key := []byte{1, 0, 0, 1, 0, 1, 1, 0}
    //oUrl := []string{"0", "x", "d", "4", "e", "d", "1", "b", "e", "5","/", 
    //                            "t", "4", "n", "4", "t", "0", "$",".", "h",
    //                            "t", "m", "l"}
    cUrl := []string{ "1", "y", "e", "5", "d", "e", "0", "c", "d", "4", ".", 
                                  "u", "5", "o", "5", "u", "1", "%", "/", "i", 
                                  "u", "l", "m"}
    //fmt.Printf("[!] We are going to cipher %s string\n", oUrl)
    //cUrl := encryptUrl(oUrl, key)
    //fmt.Printf("[*] Cipher URL: %s\n", cUrl)

    fmt.Printf("[!] We are going to decipher %s string\n", cUrl)
    dUrl := encryptUrl(cUrl, key)
    fmt.Printf("[*] Decipher URL: %s\n", dUrl)

    return 
}
