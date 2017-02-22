package dns

import (
	"encoding/binary"
	"errors"
)

type Scanner struct {
	buf [256]byte

	// Entire message being scanned.
	msg []byte

	// Byte position within the message to continue reading at.
	pos int

	// How many questions/records we've read so far.
	count int

	namelen int

	err error
}

func NewScanner(msg []byte) *Scanner {
	return &Scanner{
		msg: msg,
		pos: 12,
	}
}

// TODO(mdempsky): Consider using IANA's descriptions of the fields
// instead of the RFC 1035 field names:
// http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

func (s *Scanner) ID() uint16     { return binary.BigEndian.Uint16(s.msg) }
func (s *Scanner) Response() bool { return s.msg[2]&0x80 != 0 }
func (s *Scanner) OpCode() OpCode { return OpCode(s.msg[2] >> 3 & 0x0f) }
func (s *Scanner) AA() bool       { return s.msg[2]&0x04 != 0 }
func (s *Scanner) TC() bool       { return s.msg[2]&0x02 != 0 }
func (s *Scanner) RD() bool       { return s.msg[2]&0x01 != 0 }
func (s *Scanner) RA() bool       { return s.msg[3]&0x80 != 0 }
func (s *Scanner) Z() uint8       { return s.msg[3] >> 4 & 0x07 }
func (s *Scanner) RCode() RCode   { return RCode(s.msg[3] & 0x0f) }

func (s *Scanner) QDCount() int { return int(binary.BigEndian.Uint16(s.msg[4:])) }
func (s *Scanner) ANCount() int { return int(binary.BigEndian.Uint16(s.msg[6:])) }
func (s *Scanner) NSCount() int { return int(binary.BigEndian.Uint16(s.msg[8:])) }
func (s *Scanner) ARCount() int { return int(binary.BigEndian.Uint16(s.msg[10:])) }

func (s *Scanner) next() {
	if s.count > int(s.QDCount()) {
		s.pos += 10 + s.rdlen()
	} else if s.count > 0 {
		s.pos += 4
	}

	nl, read := s.readName(s.msg[s.pos:], &s.buf)
	s.namelen = nl
	s.pos += read

	s.count++
}

func (s *Scanner) readName(data []byte, buf *[256]byte) (int, int) {
	namelen, read := 0, 0
	orig := data

	for loop := 0; loop < 100; loop++ {
		if len(data) == 0 {
			return 0, 0
		}
		x := data[0]
		data = data[1:]

		if x >= 192 {
			pos := int(x-192) << 8

			if len(data) == 0 {
				return 0, 0
			}
			pos += int(data[0])
			data = data[1:]

			if read == 0 {
				read = len(orig) - len(data)
			}

			if pos > len(s.msg) {
				return 0, 0
			}
			data = s.msg[pos:]
			continue
		} else if x >= 64 {
			return 0, 0
		}

		if int(x) > len(data) {
			return 0, 0
		}
		if namelen+1+int(x) > len(*buf) {
			return 0, 0
		}
		buf[namelen] = x
		copy(buf[namelen+1:], data[:x])
		data = data[x:]
		namelen += 1 + int(x)

		if x == 0 {
			if read == 0 {
				read = len(orig) - len(data)
			}
			return namelen, read
		}
	}

	// Looped too long.
	return 0, 0
}

func (s *Scanner) skipQuestions() bool {
	for s.count < s.QDCount() && s.err == nil {
		s.next()
	}
	return s.err == nil
}

func (s *Scanner) Answer() bool {
	if !s.skipQuestions() {
		return false
	}
	if s.count >= s.QDCount()+s.ANCount() {
		return false
	}
	s.next()
	return s.err == nil
}

func (s *Scanner) Name() Name {
	return Name(s.buf[:s.namelen])
}

func (s *Scanner) Type() Type {
	return Type(binary.BigEndian.Uint16(s.msg[s.pos:]))
}

func (s *Scanner) Class() Class {
	return Class(binary.BigEndian.Uint16(s.msg[s.pos+2:]))
}

func (s *Scanner) TTL() uint32 {
	return binary.BigEndian.Uint32(s.msg[s.pos+4:])
}

func (s *Scanner) rdlen() int {
	return int(binary.BigEndian.Uint16(s.msg[s.pos+8:]))
}

func (s *Scanner) Err() error {
	// TODO(mdempsky): Set err.
	return s.err
}

var (
	errBadData  = errors.New("bad rdata")
	errBadField = errors.New("bad field type")
)

func (s *Scanner) Decode(fields ...interface{}) error {
	data := s.msg[s.pos+10 : s.pos+10+s.rdlen()]

	for _, f := range fields {
		switch f := f.(type) {
		case *uint16:
			if len(data) < 2 {
				return errBadData
			}
			*f = binary.BigEndian.Uint16(data)
			data = data[2:]
		case *[4]byte:
			if len(data) < len(*f) {
				return errBadData
			}
			n := copy(f[:], data)
			data = data[n:]
		case *[16]byte:
			if len(data) < len(*f) {
				return errBadData
			}
			n := copy(f[:], data)
			data = data[n:]
		case *Name:
			// TODO(mdempsky): Can this allocation be
			// avoided without uglifying the API?
			var buf [256]byte
			nl, read := s.readName(data, &buf)
			if read == 0 {
				return errBadData
			}
			*f = buf[:nl]
			data = data[read:]
		default:
			return errBadField
		}
	}

	if len(data) != 0 {
		return errBadData
	}
	return nil
}
