package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// PricingEntry holds the USD cost per 1 million tokens for a model.
type PricingEntry struct {
	PromptPerM     float64 `json:"prompt_per_m"`     // USD per 1M prompt tokens
	CompletionPerM float64 `json:"completion_per_m"` // USD per 1M completion tokens
}

// PricingTable is the in-memory fallback pricing lookup.
// Used only when OpenRouter's response does not include usage.cost.
type PricingTable struct {
	entries map[string]PricingEntry
}

// defaultPricing is the embedded pricing table shipped with the binary.
// Accuracy is best-effort; the source of truth is OpenRouter's usage.cost.
var defaultPricing = map[string]PricingEntry{
	"openai/gpt-4o":                         {PromptPerM: 2.50, CompletionPerM: 10.00},
	"openai/gpt-4o-mini":                    {PromptPerM: 0.15, CompletionPerM: 0.60},
	"anthropic/claude-sonnet-4.6":           {PromptPerM: 3.00, CompletionPerM: 15.00},
	"anthropic/claude-haiku-4.5":            {PromptPerM: 1.00, CompletionPerM: 5.00},
	"google/gemini-flash-latest":            {PromptPerM: 1.50, CompletionPerM: 6.00},
	"meta-llama/llama-3.2-3b-instruct":      {PromptPerM: 0.051, CompletionPerM: 0.051},
	"meta-llama/llama-3.2-3b-instruct:free": {PromptPerM: 0.0, CompletionPerM: 0.0},
}

// LoadPricingTable loads a pricing JSON file from disk. If the file does not
// exist, a warning is logged and the embedded defaultPricing is used as a
// base (the caller can extend it).
func LoadPricingTable(path string) (*PricingTable, error) {
	entries := make(map[string]PricingEntry, len(defaultPricing))
	// Start with built-in defaults
	for k, v := range defaultPricing {
		entries[k] = v
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("pricing file not found; using built-in defaults", "path", path)
			return &PricingTable{entries: entries}, nil
		}
		return nil, fmt.Errorf("pricing: reading %s: %w", path, err)
	}

	var fileEntries map[string]PricingEntry
	if err := json.Unmarshal(data, &fileEntries); err != nil {
		return nil, fmt.Errorf("pricing: parsing %s: %w", path, err)
	}

	// File entries override the defaults
	for k, v := range fileEntries {
		entries[k] = v
	}

	return &PricingTable{entries: entries}, nil
}

// NewDefaultPricingTable returns a PricingTable pre-loaded with the built-in defaults.
func NewDefaultPricingTable() *PricingTable {
	entries := make(map[string]PricingEntry, len(defaultPricing))
	for k, v := range defaultPricing {
		entries[k] = v
	}
	return &PricingTable{entries: entries}
}

// Cost returns the estimated USD cost for a given model and token counts.
// Returns (cost, true) if the model is known; (0, false) if it is not.
func (t *PricingTable) Cost(model string, promptTok, completionTok int) (float64, bool) {
	entry, ok := t.entries[model]
	if !ok {
		return 0, false
	}
	cost := (float64(promptTok)/1_000_000)*entry.PromptPerM +
		(float64(completionTok)/1_000_000)*entry.CompletionPerM
	return cost, true
}
