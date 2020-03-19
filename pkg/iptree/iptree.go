package iptree

import (
	"fmt"
	"net"
	"strings"
	"time"

	iradix "github.com/hashicorp/go-immutable-radix"
)

// IPTree ...
type IPTree struct {
	IPv4 *iradix.Tree
	IPv6 *iradix.Tree
}

// FlatJSON ...
type FlatJSON struct {
	IPv4 map[string]time.Time `json:"ipv4"`
	IPv6 map[string]time.Time `json:"ipv6"`
}

// New ...
func New() *IPTree {
	IPv4Tree := iradix.New()
	IPv6Tree := iradix.New()
	return &IPTree{
		IPv4: IPv4Tree,
		IPv6: IPv6Tree,
	}
}

// GetIP returns the expiration time
func (ipTree *IPTree) GetIP(ip net.IP) (time.Time, bool) {
	switch {
	case ipTree.isIPv4(ip):
		if expireAt, ok := ipTree.IPv4.Get([]byte(ip.String())); ok {
			return expireAt.(time.Time), ok
		}
	case ipTree.isIPv6(ip):
		if expireAt, ok := ipTree.IPv6.Get([]byte(ip.String())); ok {
			return expireAt.(time.Time), ok
		}
	}
	return time.Time{}, false
}

// TODO cleanup old entries
func garbageCollector() {}

// AddCIDR TODO
func (ipTree *IPTree) AddCIDR() error {
	return fmt.Errorf("not implemented")
}

// AddIP ...
func (ipTree *IPTree) AddIP(ip net.IP, expireAt time.Time) error {
	switch {
	case ipTree.isIPv4(ip):
		ipTree.IPv4, _, _ = ipTree.IPv4.Insert([]byte(ip.String()), expireAt)
	case ipTree.isIPv6(ip):
		ipTree.IPv6, _, _ = ipTree.IPv6.Insert([]byte(ip.String()), expireAt)
	default:
		return fmt.Errorf("Could not parse IP")
	}
	return nil
}

func (ipTree *IPTree) isIPv4(ip net.IP) bool {
	return strings.Count(ip.String(), ".") == 3
}

func (ipTree *IPTree) isIPv6(ip net.IP) bool {
	return strings.Count(ip.String(), ":") >= 2
}

// ToFlatJSON returns the tree represented in a flat JSON format.
func (ipTree *IPTree) ToFlatJSON() (FlatJSON, error) {
	flatJSON := FlatJSON{
		IPv4: make(map[string]time.Time),
		IPv6: make(map[string]time.Time),
	}

	it := ipTree.IPv4.Root().Iterator()
	for key, expireAt, ok := it.Next(); ok; key, _, ok = it.Next() {
		flatJSON.IPv4[string(key)] = expireAt.(time.Time)
	}

	it = ipTree.IPv6.Root().Iterator()
	for key, expireAt, ok := it.Next(); ok; key, _, ok = it.Next() {
		flatJSON.IPv6[string(key)] = expireAt.(time.Time)
	}

	return flatJSON, nil
}
