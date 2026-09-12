package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	data, _ := os.ReadFile(os.Args[1])
	fmt.Println(string(data))
}
