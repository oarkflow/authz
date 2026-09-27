package stores

import "testing"

// TestMemoryStoresConformance runs conformance tests against memory stores.
func TestMemoryStoresConformance(t *testing.T) {
	suite := NewMemoryTestSuite()
	defer suite.Cleanup()
	suite.RunAllTests(t)
}
