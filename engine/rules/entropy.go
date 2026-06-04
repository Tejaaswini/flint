package rules

import "math"

// shannonEntropy computes the Shannon entropy of s in bits per character.
// Returns 0 for empty strings.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	total := 0
	for _, c := range s {
		freq[c]++
		total++
	}
	var h float64
	for _, count := range freq {
		p := float64(count) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

// isHighEntropy returns true if s has Shannon entropy >= threshold bits/char.
func isHighEntropy(s string, threshold float64) bool {
	return shannonEntropy(s) >= threshold
}
