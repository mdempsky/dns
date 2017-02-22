package dns

type Data interface {
	Unmarshal(s *Scanner) error
}

type DataA struct {
	A [4]byte
}

func (d *DataA) Unmarshal(s *Scanner) error {
	return s.Decode(&d.A)
}

type DataAAAA struct {
	A [16]byte
}

func (d *DataAAAA) Unmarshal(s *Scanner) error {
	return s.Decode(&d.A)
}

type DataMX struct {
	Pref     uint16
	Exchange Name
}

func (d *DataMX) Unmarshal(s *Scanner) error {
	return s.Decode(&d.Pref, &d.Exchange)
}
