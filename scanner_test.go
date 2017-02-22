package dns_test

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"

	"github.com/mdempsky/dns"
)

func ExampleScanner() {
	qname := dns.Name("\x03www\x06google\x03com\x00")

	msg, err := hex.DecodeString("1acb818000010002000000010377777706676f6f676c6503636f6d0000ff0001c00c000100010000012c0004d83ac344c00c001c00010000012c00102607f8b04005080700000000000020040000291000000000000000")
	if err != nil {
		panic(err)
	}

	var addrs []net.IP
	scanner := dns.NewScanner(msg)
	for scanner.Answer() {
		if scanner.Class() != dns.ClassIN || !scanner.Name().Equals(qname) {
			continue
		}
		switch scanner.Type() {
		case dns.TypeA:
			var d dns.DataA
			if err := d.Unmarshal(scanner); err != nil {
				panic(err)
			}
			addrs = append(addrs, net.IPv4(d.A[0], d.A[1], d.A[2], d.A[3]))
		case dns.TypeAAAA:
			var d dns.DataAAAA
			if err := d.Unmarshal(scanner); err != nil {
				panic(err)
			}
			addrs = append(addrs, append([]byte(nil), d.A[:]...))
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	fmt.Println(addrs)

	// Output:
	// [216.58.195.68 2607:f8b0:4005:807::2004]
}

func BenchmarkScanner(b *testing.B) {
	qname := dns.Name("\x03www\x06google\x03com\x00")

	msg, err := hex.DecodeString("1acb818000010002000000010377777706676f6f676c6503636f6d0000ff0001c00c000100010000012c0004d83ac344c00c001c00010000012c00102607f8b04005080700000000000020040000291000000000000000")
	if err != nil {
		panic(err)
	}

	for i := 0; i < b.N; i++ {
		scanner := dns.NewScanner(msg)
		for scanner.Answer() {
			if scanner.Class() != dns.ClassIN || !scanner.Name().Equals(qname) {
				continue
			}
			switch scanner.Type() {
			case dns.TypeA:
				var d dns.DataA
				if err := d.Unmarshal(scanner); err != nil {
					panic(err)
				}
			case dns.TypeAAAA:
				var d dns.DataAAAA
				if err := d.Unmarshal(scanner); err != nil {
					panic(err)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}
}
