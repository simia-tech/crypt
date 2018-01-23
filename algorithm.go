package crypt

// Algorithm defines a algorithm.
type Algorithm func (string, string) (string, error)

var algorithms = map[string]Algorithm{}

// RegisterAlgorithm registers an algorithm under the provided prefix.
func RegisterAlgorithm(prefix string, algorithm Algorithm) {
  algorithms[prefix] = algorithm
}
