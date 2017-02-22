package dns

// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

// TODO(mdempsky): Evaluate naming scheme and inclusion criteria.

type Class uint16

const (
	// Resource record classes.
	ClassIN Class = 1 // Internet (IN)
	ClassCH Class = 3 // Chaos (CH)
	ClassHS Class = 4 // Hesiod (HS)

	// Query classes.
	ClassANY Class = 255
)

type Type uint16

const (
	// Resource record types.
	TypeA     Type = 1  // a host address
	TypeNS    Type = 2  // an authoritative name server
	TypeCNAME Type = 5  // the canonical name for an alias
	TypeSOA   Type = 6  // marks the start of a zone of authority
	TypePTR   Type = 12 // a domain name pointer
	TypeMX    Type = 15 // mail exchange
	TypeTXT   Type = 16 // text strings
	TypeAAAA  Type = 28 // IP6 Address
	TypeSRV   Type = 33 // Server Selection
	TypeOPT   Type = 41

	// Query types.
	TypeAXFR Type = 252 // transfer of an entire zone
	TypeANY  Type = 255
)

type OpCode int

const (
	OpQuery  OpCode = iota // a standard query
	OpIQuery               // an inverse query
	OpStatus               // a server status request
	_
	OpNotify
	OpUpdate
)

type RCode int

const (
	RNoError RCode = iota
	RFormErr
	RServFail
	RNXDomain
	RNotImp
	RRefused
)
