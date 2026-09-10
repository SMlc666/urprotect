package main

import "fmt"

func main() {
	const value uint64 = 0x0123456789abcdef
	fmt.Println("urprotect-fixture:go")
	fmt.Printf("checksum=%016x\n", (value<<7)|(value>>57))
}
