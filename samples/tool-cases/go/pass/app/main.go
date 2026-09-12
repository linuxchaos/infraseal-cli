package main

import "fmt"

func main() {
	approved := map[string]string{
		"refund": "Refund requests are reviewed within 14 days and depend on account eligibility.",
	}
	fmt.Println(approved["refund"])
}
