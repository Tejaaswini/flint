package main

// EstimateBaselineCost computes the counterfactual cost if the baseline model
// had been used for the same request. It uses the PricingTable for the lookup.
// Returns 0 if the baseline model is not found in the table.
func EstimateBaselineCost(pricing *PricingTable, promptTokens, completionTokens int, baselineModel string) float64 {
	cost, _ := pricing.Cost(baselineModel, promptTokens, completionTokens)
	return cost
}
