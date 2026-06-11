package xns

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

const onionVersion = byte(3)

func NameFromHost(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if !strings.HasSuffix(host, ".xns") {
		return "", false
	}
	labels := strings.Split(strings.TrimSuffix(host, ".xns"), ".")
	if len(labels) == 0 {
		return "", false
	}
	for _, label := range labels[:len(labels)-1] {
		if !validHostLabel(label) {
			return "", false
		}
	}
	name := labels[len(labels)-1]
	if ValidName(name) != nil {
		return "", false
	}
	return name, true
}

func ValidName(name string) error {
	if len(name) < 1 || len(name) > 32 {
		return errors.New("name must be 1..32 bytes")
	}
	for i := range len(name) {
		c := name[i]
		if !isNameEdge(c) && c != '-' {
			return errors.New("name may only contain lowercase a-z, 0-9, and -")
		}
	}
	if !isNameEdge(name[0]) || !isNameEdge(name[len(name)-1]) {
		return errors.New("name must start and end with a lowercase letter or digit")
	}
	return nil
}

func OnionFromOwnerKey(ownerHex string) (string, error) {
	owner, err := hex.DecodeString(ownerHex)
	if err != nil {
		return "", err
	}
	if len(owner) != 32 {
		return "", errors.New("owner key must be 32 bytes")
	}
	if err := validOwnerPoint(owner); err != nil {
		return "", err
	}

	checksumInput := append([]byte(".onion checksum"), owner...)
	checksumInput = append(checksumInput, onionVersion)
	sum := sha3.Sum256(checksumInput)
	raw := make([]byte, 0, 35)
	raw = append(raw, owner...)
	raw = append(raw, sum[:2]...)
	raw = append(raw, onionVersion)
	hostname := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return strings.ToLower(hostname) + ".onion", nil
}

func isNameEdge(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

func validHostLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 {
		return false
	}
	for i := range len(label) {
		if !isNameEdge(label[i]) && label[i] != '-' {
			return false
		}
	}
	return isNameEdge(label[0]) && isNameEdge(label[len(label)-1])
}

func invalidPoint(reason string) error {
	return fmt.Errorf("invalid Ed25519 owner key: %s", reason)
}
