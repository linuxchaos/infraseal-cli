package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	policyPath := filepath.Join(root, ".infraseal", "evidence", "knowledge-base.md")
	data, err := os.ReadFile(policyPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Loaded approved policy evidence (%d bytes).\n", len(data))
}
