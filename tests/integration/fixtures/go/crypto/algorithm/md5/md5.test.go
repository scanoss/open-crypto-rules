// TEST-RULE: go.crypto.md5.hash-usage
// TEST-METADATA: algorithmName=MD5, algorithmFamily=MD5, library=crypto/md5

package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	h := md5.New()
	h.Write([]byte("hello world"))
	fmt.Printf("%x\n", h.Sum(nil))
}
