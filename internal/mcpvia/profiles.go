package mcpvia

import "strings"

var profiles = []string{"quick", "rag", "agent", "governance", "full"}

func ValidProfile(value string) bool {
	for _, profile := range profiles {
		if strings.EqualFold(profile, value) {
			return true
		}
	}
	return false
}

func Profiles() []string { return append([]string{}, profiles...) }
