package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"

	"golang.org/x/crypto/sha3"
)

func generateHashes(euisArray [][]byte) [][]byte {
	hashesArray := make([][]byte, 0)

	for _, eui := range euisArray {

		md5Sum := md5.Sum(eui)

		sha1Sum := sha1.Sum(eui)

		sha2Sum := sha256.Sum256(eui)

		sha3_256Sum := sha3.Sum256(eui)

		sha3_224Sum := sha3.Sum224(eui)

		// Add first 16 bytes of the hashes
		hashesArray = append(hashesArray, md5Sum[:16], sha1Sum[:16], sha2Sum[:16], sha3_256Sum[:16], sha3_224Sum[:16])

		// Add last 16 bytes of the hashes
		hashesArray = append(hashesArray, md5Sum[len(md5Sum)-16:], sha1Sum[len(sha1Sum)-16:], sha2Sum[len(sha2Sum)-16:], sha3_256Sum[len(sha3_256Sum)-16:], sha3_224Sum[len(sha3_224Sum)-16:])

	}

	return hashesArray
}
