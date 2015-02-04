// The macaroon package implements macaroons as described in
// the paper "Macaroons: Cookies with Contextual Caveats for
// Decentralized Authorization in the Cloud"
// (http://theory.stanford.edu/~ataly/Papers/macaroons.pdf)
//
// See the macaroon bakery packages at http://godoc.org/gopkg.in/macaroon-bakery.v0
// for higher level services and operations that use macaroons.
package macaroon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// Macaroon holds a macaroon.
// See Fig. 7 of http://theory.stanford.edu/~ataly/Papers/macaroons.pdf
// for a description of the data contained within.
// Macaroons are mutable objects - use Clone as appropriate
// to avoid unwanted mutation.
type Macaroon struct {
	// data holds the binary-marshalled form
	// of the macaroon data.
	data []byte

	location packet
	id       packet
	caveats  packet
	sig      []byte
}

// New returns a new macaroon with the given root key,
// identifier and location.
func New(rootKey []byte, id, loc string) (*Macaroon, error) {
	var m Macaroon
	if err := m.init(id, loc); err != nil {
		return nil, err
	}
	m.sig = keyedHash(rootKey, m.dataBytes(m.id))
	return &m, nil
}

func (m *Macaroon) init(id, loc string) error {
	var ok bool
	m.location, ok = m.appendPacket(fieldLocation, []byte(loc))
	if !ok {
		return fmt.Errorf("macaroon location too big")
	}
	m.id, ok = m.appendPacket(fieldIdentifier, []byte(id))
	if !ok {
		return fmt.Errorf("macaroon identifier too big")
	}
	return nil
}

// Clone returns a copy of the receiving macaroon.
func (m *Macaroon) Clone() *Macaroon {
	m1 := *m
	// Ensure that if any data is appended to the new
	// macaroon, it will copy data and caveats.
	m1.data = m1.data[0:len(m1.data):len(m1.data)]
	m1.sig = append([]byte(nil), m.sig...)
	return &m1
}

// Location returns the macaroon's location hint. This is
// not verified as part of the macaroon.
func (m *Macaroon) Location() string {
	return m.dataStr(m.location)
}

// Id returns the id of the macaroon. This can hold
// arbitrary information.
func (m *Macaroon) Id() string {
	return m.dataStr(m.id)
}

func (m *Macaroon) caveatsRaw() []byte {
	return m.dataBytes(m.caveats)
}

// Signature returns the macaroon's signature.
func (m *Macaroon) Signature() []byte {
	return append([]byte(nil), m.sig...)
}

// Caveats returns the macaroon's caveats.
// This method will probably change, and it's important not to change the returned caveat.
func (m *Macaroon) GetCaveats(v interface{}) error {
	err := UnMarshalCaveats(v, m.caveatsRaw())

	return err
}

func (m *Macaroon) SetCaveats(v interface{}) error {
	cavData, err := MarshalCaveats(v)

	var ok bool
	if err == nil {
		m.caveats, ok = m.appendPacket(fieldCaveat, cavData)
		if ok {
			sig := keyedHasher(m.sig)
			sig.Write(cavData)
			m.sig = sig.Sum(m.sig[:0])
			return nil
		} else {
			return fmt.Errorf("caveat identifier too big")
		}
	}
	return err
}

// Bind prepares the macaroon for being used to discharge the
// macaroon with the given signature sig. This must be
// used before it is used in the discharges argument to Verify.
func (m *Macaroon) Bind(sig []byte) {
	m.sig = bindForRequest(sig, m.sig)
}

// bndForRequest binds the given macaroon
// to the given signature of its parent macaroon.
func bindForRequest(rootSig, dischargeSig []byte) []byte {
	if bytes.Equal(rootSig, dischargeSig) {
		return rootSig
	}
	sig := sha256.New()
	sig.Write(rootSig)
	sig.Write(dischargeSig)
	return sig.Sum(nil)
}

// Verify verifies that the receiving macaroon is valid.
// The root key must be the same that the macaroon was originally
// minted with.
// Verify returns nil if the verification succeeds.
func (m *Macaroon) Verify(rootKey []byte) error {
	if err := m.verify(m.sig, rootKey); err != nil {
		return err
	}
	return nil
}

func (m *Macaroon) verify(rootSig []byte, rootKey []byte) error {
	if len(rootSig) == 0 {
		rootSig = m.sig
	}
	caveatSig := keyedHash(rootKey, m.dataBytes(m.id))

	sig := keyedHasher(caveatSig)
	sig.Write(m.dataBytes(m.caveats))
	caveatSig = sig.Sum(caveatSig[:0])

	boundSig := bindForRequest(rootSig, caveatSig)
	if !hmac.Equal(boundSig, m.sig) {
		return fmt.Errorf("signature mismatch after caveat verification")
	}
	return nil
}

type Verifier interface {
	Verify(m *Macaroon, rootKey []byte) (bool, error)
}
