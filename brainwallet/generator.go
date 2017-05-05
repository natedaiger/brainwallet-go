// generator.go - Generator routines
// Copyright (c) 2015 Kamilla Productions Uninc. Author Joonas Greis  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in the LICENSE file.

package brainwallet

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math/big"
	"sync"

	"github.com/haltingstate/secp256k1-go"
	"github.com/jbenet/go-base58"
	"golang.org/x/crypto/ripemd160"
)

// Generator
func Generator(input chan string, output chan string, done chan int, wg *sync.WaitGroup) {

	defer wg.Done()

waitfordone:
	for {
		select {
		case passphrase := <-input: // Receive passphrase

			hasher := sha256.New() // SHA256
			sha := SHA256(hasher, []byte(passphrase))

			publicKeyBytes := secp256k1.UncompressedPubkeyFromSeckey(sha) // ECDSA
			privateKey := hex.EncodeToString(sha)                         // Store Private Key
			// wif := base58.Encode(bigintPrivKey.Bytes())
			wif := b58checkencode(0x80, sha)

			sha = SHA256(hasher, publicKeyBytes) // SHA256
			ripe := RIPEMD160(sha)               // RIPEMD160

			versionripe := "00" + hex.EncodeToString(ripe) // Add version byte 0x00
			decoded, _ := hex.DecodeString(versionripe)

			sha = SHA256(hasher, SHA256(hasher, decoded)) // SHA256x2

			addressChecksum := hex.EncodeToString(sha)[0:8] // Concencate Address Checksum and Extended RIPEMD160 Hash
			hexBitcoinAddress := versionripe + addressChecksum

			bigintBitcoinAddress, _ := new(big.Int).SetString((hexBitcoinAddress), 16) // Base58Encode the Address
			base58BitcoinAddress := base58.Encode(bigintBitcoinAddress.Bytes())

			// line := "1" + base58BitcoinAddress + ":" + privateKey + ":" + wif + ":" + passphrase // Create a line for io output
			line := "1" + base58BitcoinAddress + ":" + privateKey + ":" + wif // Create a line for io output
			line = wif
			output <- line // Send line to output channel

		case <-done: // Everything is done. Break out from the loop.
			break waitfordone
		}
	}
}

// b58checkencode encodes version ver and byte slice b into a base-58 check encoded string.
func b58checkencode(ver uint8, b []byte) (s string) {
	/* Prepend version */
	bcpy := append([]byte{ver}, b...)

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* SHA256 Hash #1 */
	sha256_h.Reset()
	sha256_h.Write(bcpy)
	hash1 := sha256_h.Sum(nil)

	/* SHA256 Hash #2 */
	sha256_h.Reset()
	sha256_h.Write(hash1)
	hash2 := sha256_h.Sum(nil)

	/* Append first four bytes of hash */
	bcpy = append(bcpy, hash2[0:4]...)

	/* Encode base58 string */
	s = b58encode(bcpy)

	/* For number of leading 0's in bytes, prepend 1 */
	for _, v := range bcpy {
		if v != 0 {
			break
		}
		s = "1" + s
	}

	return s
}

func b58encode(b []byte) (s string) {
	/* See https://en.bitcoin.it/wiki/Base58Check_encoding */

	const BITCOIN_BASE58_TABLE = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	/* Convert big endian bytes to big int */
	x := new(big.Int).SetBytes(b)

	/* Initialize */
	r := new(big.Int)
	m := big.NewInt(58)
	zero := big.NewInt(0)
	s = ""

	/* Convert big int to string */
	for x.Cmp(zero) > 0 {
		/* x, r = (x / 58, x % 58) */
		x.QuoRem(x, m, r)
		/* Prepend ASCII character */
		s = string(BITCOIN_BASE58_TABLE[r.Int64()]) + s
	}

	return s
}

// SHA256 Hasher function
func SHA256(hasher hash.Hash, input []byte) (hash []byte) {

	hasher.Reset()
	hasher.Write(input)
	hash = hasher.Sum(nil)
	return hash

}

// RIPEMD160 Hasher function
func RIPEMD160(input []byte) (hash []byte) {

	riper := ripemd160.New()
	riper.Write(input)
	hash = riper.Sum(nil)
	return hash

}
