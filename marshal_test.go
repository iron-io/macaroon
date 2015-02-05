package macaroon_test

import (
	"bytes"

	gc "gopkg.in/check.v1"

	"github.com/iron-io/macaroon"
)

type marshalSuite struct{}

var _ = gc.Suite(&marshalSuite{})

func (*marshalSuite) TestMarshalUnmarshalMacaroon(c *gc.C) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), []byte("a location"))

	err := m.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, gc.IsNil)

	b, err := m.MarshalBinary()
	c.Assert(err, gc.IsNil)

	unmarshaledM := &macaroon.Macaroon{}
	err = unmarshaledM.UnmarshalBinary(b)
	c.Assert(err, gc.IsNil)

	c.Assert(bytes.Compare(m.Location(), unmarshaledM.Location()), gc.Equals, 0)
	c.Assert(bytes.Compare(m.Id(), unmarshaledM.Id()), gc.Equals, 0)

	c.Assert(m.Signature(), gc.DeepEquals, unmarshaledM.Signature())
	c.Assert(m.Caveats(), gc.DeepEquals, unmarshaledM.Caveats())
	c.Assert(m, gc.DeepEquals, unmarshaledM)
}

func (*marshalSuite) TestMarshalUnmarshalSlice(c *gc.C) {
	rootKey := []byte("secret")
	m1 := MustNew(rootKey, []byte("some id"), []byte("a location"))
	m2 := MustNew(rootKey, []byte("some other id"), []byte("another location"))

	err := m1.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, gc.IsNil)
	err = m2.AddFirstPartyCaveat([]byte("another caveat"))
	c.Assert(err, gc.IsNil)

	macaroons := macaroon.Slice{m1, m2}

	b, err := macaroons.MarshalBinary()
	c.Assert(err, gc.IsNil)

	var unmarshaledMacs macaroon.Slice
	err = unmarshaledMacs.UnmarshalBinary(b)
	c.Assert(err, gc.IsNil)

	c.Assert(unmarshaledMacs, gc.HasLen, len(macaroons))
	for i, m := range macaroons {
		c.Assert(bytes.Compare(m.Location(), unmarshaledMacs[i].Location()), gc.Equals, 0)
		c.Assert(bytes.Compare(m.Id(), unmarshaledMacs[i].Id()), gc.Equals, 0)

		c.Assert(m.Signature(), gc.DeepEquals, unmarshaledMacs[i].Signature())
		c.Assert(m.Caveats(), gc.DeepEquals, unmarshaledMacs[i].Caveats())
	}
	c.Assert(macaroons, gc.DeepEquals, unmarshaledMacs)

	// The unmarshaled macaroons share the same underlying data
	// slice, so check that appending a caveat to the first does not
	// affect the second.
	for i := 0; i < 10; i++ {
		err = unmarshaledMacs[0].AddFirstPartyCaveat([]byte("caveat"))
		c.Assert(err, gc.IsNil)
	}
	c.Assert(unmarshaledMacs[1], gc.DeepEquals, macaroons[1])
	c.Assert(err, gc.IsNil)
}

func (*marshalSuite) TestSliceRoundtrip(c *gc.C) {
	rootKey := []byte("secret")
	m1 := MustNew(rootKey, []byte("some id"), []byte("a location"))
	m2 := MustNew(rootKey, []byte("some other id"), []byte("another location"))

	err := m1.AddFirstPartyCaveat([]byte("a caveat"))
	c.Assert(err, gc.IsNil)
	err = m2.AddFirstPartyCaveat([]byte("another caveat"))
	c.Assert(err, gc.IsNil)

	macaroons := macaroon.Slice{m1, m2}

	b, err := macaroons.MarshalBinary()
	c.Assert(err, gc.IsNil)

	var unmarshaledMacs macaroon.Slice
	err = unmarshaledMacs.UnmarshalBinary(b)
	c.Assert(err, gc.IsNil)

	marshaledMacs, err := unmarshaledMacs.MarshalBinary()
	c.Assert(err, gc.IsNil)

	c.Assert(b, gc.DeepEquals, marshaledMacs)
}
