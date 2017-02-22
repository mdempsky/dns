package dns

// A Name is a domain name in wire format.
type Name []byte

// Equals reports whether n and x denote equal domain names.
func (n Name) Equals(x Name) bool {
	if len(n) != len(x) {
		return false
	}
	for i, c1 := range n {
		c2 := x[i]
		if c1 == c2 {
			continue
		}

		if c1 >= 'a' && c1 <= 'z' {
			c1 -= 'a' - 'A'
		}
		if c2 >= 'a' && c2 <= 'z' {
			c2 -= 'a' - 'A'
		}
		if c1 != c2 {
			return false
		}
	}
	return true
}
