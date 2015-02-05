package macaroon_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	gc "gopkg.in/check.v1"

	"github.com/iron-io/macaroon"
)

func TestMacaroonLength(t *testing.T) {
	m, _ := macaroon.New([]byte("secret"), []byte(""), []byte(""))
	const expectedLength = 29
	buf, _ := m.MarshalBinary()
	if n := len(buf); n != expectedLength {
		t.Errorf("expected length %v; got %v\n", expectedLength, n)
	}
}

func TestPackage(t *testing.T) {
	gc.TestingT(t)
}

type macaroonSuite struct{}

var _ = gc.Suite(&macaroonSuite{})

func never(string) error {
	return fmt.Errorf("condition is never true")
}

func (*macaroonSuite) TestNoCaveats(c *gc.C) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), []byte("a location"))
	c.Assert(bytes.Compare(m.Location(), []byte("a location")), gc.Equals, 0)
	c.Assert(bytes.Compare(m.Id(), []byte("some id")), gc.Equals, 0)

	err := m.Verify(rootKey, never, nil)
	c.Assert(err, gc.IsNil)
}

func (*macaroonSuite) TestFirstPartyCaveat(c *gc.C) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), []byte("a location"))

	caveats := map[string]bool{
		"a caveat":       true,
		"another caveat": true,
	}
	tested := make(map[string]bool)

	for cav := range caveats {
		m.AddFirstPartyCaveat([]byte(cav))
	}
	expectErr := fmt.Errorf("condition not met")
	check := func(cav string) error {
		tested[cav] = true
		if caveats[cav] {
			return nil
		}
		return expectErr
	}
	err := m.Verify(rootKey, check, nil)
	c.Assert(err, gc.IsNil)

	c.Assert(tested, gc.DeepEquals, caveats)

	m.AddFirstPartyCaveat([]byte("not met"))
	err = m.Verify(rootKey, check, nil)
	c.Assert(err, gc.Equals, expectErr)

	c.Assert(tested["not met"], gc.Equals, true)
}

func (*macaroonSuite) TestThirdPartyCaveat(c *gc.C) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), []byte("a location"))

	dischargeRootKey := []byte("shared root key")
	thirdPartyCaveatId := []byte("3rd party caveat")
	err := m.AddThirdPartyCaveat(dischargeRootKey, thirdPartyCaveatId, "remote.com")
	c.Assert(err, gc.IsNil)

	dm := MustNew(dischargeRootKey, thirdPartyCaveatId, []byte("remote location"))
	dm.Bind(m.Signature())
	err = m.Verify(rootKey, never, []*macaroon.Macaroon{dm})
	c.Assert(err, gc.IsNil)
}

func (*macaroonSuite) TestThirdPartyCaveatBadRandom(c *gc.C) {
	rootKey := []byte("secret")
	m := MustNew(rootKey, []byte("some id"), []byte("a location"))
	dischargeRootKey := []byte("shared root key")
	thirdPartyCaveatId := []byte("3rd party caveat")

	err := macaroon.AddThirdPartyCaveatWithRand(m, dischargeRootKey, thirdPartyCaveatId, "remote.com", &macaroon.ErrorReader{})
	c.Assert(err, gc.ErrorMatches, "cannot generate random bytes: fail")
}

type conditionTest struct {
	conditions map[string]bool
	expectErr  string
}

var verifyTests = []struct {
	about      string
	macaroons  []macaroonSpec
	conditions []conditionTest
}{{
	about: "single third party caveat without discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: `cannot find discharge macaroon for caveat "bob-is-great"`,
	}},
}, {
	about: "single third party caveat with discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful": false,
		},
		expectErr: `condition "wonderful" not met`,
	}},
}, {
	about: "single third party caveat with discharge with mismatching root key",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key-wrong",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: `signature mismatch after caveat verification`,
	}},
}, {
	about: "single third party caveat with two discharges",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "top of the world",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": true,
		},
		expectErr: `discharge macaroon "bob-is-great" was not used`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         false,
			"top of the world": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": false,
		},
		expectErr: `discharge macaroon "bob-is-great" was not used`,
	}},
}, {
	about: "one discharge used for two macaroons",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "somewhere else",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}, {
			condition: "bob-is-great",
			location:  "charlie",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "somewhere else",
		caveats: []caveat{{
			condition: "bob-is-great",
			location:  "charlie",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
	}},
	conditions: []conditionTest{{
		expectErr: `discharge macaroon "bob-is-great" was used more than once`,
	}},
}, {
	about: "recursive third party caveat",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "bob-is-great",
			location:  "charlie",
			rootKey:   "bob-caveat-root-key",
		}},
	}},
	conditions: []conditionTest{{
		expectErr: `discharge macaroon "bob-is-great" was used more than once`,
	}},
}, {
	about: "two third party caveats",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}, {
			condition: "charlie-is-great",
			location:  "charlie",
			rootKey:   "charlie-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}},
	}, {
		location: "charlie",
		rootKey:  "charlie-caveat-root-key",
		id:       "charlie-is-great",
		caveats: []caveat{{
			condition: "top of the world",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         false,
			"top of the world": true,
		},
		expectErr: `condition "splendid" not met`,
	}, {
		conditions: map[string]bool{
			"wonderful":        true,
			"splendid":         true,
			"top of the world": false,
		},
		expectErr: `condition "top of the world" not met`,
	}},
}, {
	about: "third party caveat with undischarged third party caveat",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}, {
			condition: "bob-is-great",
			location:  "bob",
			rootKey:   "bob-caveat-root-key",
		}},
	}, {
		location: "bob",
		rootKey:  "bob-caveat-root-key",
		id:       "bob-is-great",
		caveats: []caveat{{
			condition: "splendid",
		}, {
			condition: "barbara-is-great",
			location:  "barbara",
			rootKey:   "barbara-caveat-root-key",
		}},
	}},
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful": true,
			"splendid":  true,
		},
		expectErr: `cannot find discharge macaroon for caveat "barbara-is-great"`,
	}},
}, {
	about:     "recursive third party caveats",
	macaroons: recursiveThirdPartyCaveatMacaroons,
	conditions: []conditionTest{{
		conditions: map[string]bool{
			"wonderful":   true,
			"splendid":    true,
			"high-fiving": true,
			"spiffing":    true,
		},
	}, {
		conditions: map[string]bool{
			"wonderful":   true,
			"splendid":    true,
			"high-fiving": false,
			"spiffing":    true,
		},
		expectErr: `condition "high-fiving" not met`,
	}},
}, {
	about: "unused discharge",
	macaroons: []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
	}, {
		rootKey: "other-key",
		id:      "unused",
	}},
	conditions: []conditionTest{{
		expectErr: `discharge macaroon "unused" was not used`,
	}},
}}

var recursiveThirdPartyCaveatMacaroons = []macaroonSpec{{
	rootKey: "root-key",
	id:      "root-id",
	caveats: []caveat{{
		condition: "wonderful",
	}, {
		condition: "bob-is-great",
		location:  "bob",
		rootKey:   "bob-caveat-root-key",
	}, {
		condition: "charlie-is-great",
		location:  "charlie",
		rootKey:   "charlie-caveat-root-key",
	}},
}, {
	location: "bob",
	rootKey:  "bob-caveat-root-key",
	id:       "bob-is-great",
	caveats: []caveat{{
		condition: "splendid",
	}, {
		condition: "barbara-is-great",
		location:  "barbara",
		rootKey:   "barbara-caveat-root-key",
	}},
}, {
	location: "charlie",
	rootKey:  "charlie-caveat-root-key",
	id:       "charlie-is-great",
	caveats: []caveat{{
		condition: "splendid",
	}, {
		condition: "celine-is-great",
		location:  "celine",
		rootKey:   "celine-caveat-root-key",
	}},
}, {
	location: "barbara",
	rootKey:  "barbara-caveat-root-key",
	id:       "barbara-is-great",
	caveats: []caveat{{
		condition: "spiffing",
	}, {
		condition: "ben-is-great",
		location:  "ben",
		rootKey:   "ben-caveat-root-key",
	}},
}, {
	location: "ben",
	rootKey:  "ben-caveat-root-key",
	id:       "ben-is-great",
}, {
	location: "celine",
	rootKey:  "celine-caveat-root-key",
	id:       "celine-is-great",
	caveats: []caveat{{
		condition: "high-fiving",
	}},
}}

func (*macaroonSuite) TestVerify(c *gc.C) {
	for i, test := range verifyTests {
		c.Logf("test %d: %s", i, test.about)
		rootKey, primary, discharges := makeMacaroons(test.macaroons)
		for _, cond := range test.conditions {
			c.Logf("conditions %#v", cond.conditions)
			check := func(cav string) error {
				if cond.conditions[cav] {
					return nil
				}
				return fmt.Errorf("condition %q not met", cav)
			}
			err := primary.Verify(
				rootKey,
				check,
				discharges,
			)
			if cond.expectErr != "" {
				c.Assert(err, gc.ErrorMatches, cond.expectErr)
			} else {
				c.Assert(err, gc.IsNil)
			}

			// Cloned macaroon should have same verify result.
			cloneErr := primary.Clone().Verify(rootKey, check, discharges)
			c.Assert(cloneErr, gc.DeepEquals, err)
		}
	}
}

func (*macaroonSuite) TestMarshalJSON(c *gc.C) {
	rootKey := []byte("secret")
	m0 := MustNew(rootKey, []byte("some id"), []byte("a location"))
	m0.AddFirstPartyCaveat([]byte("account = 3735928559"))
	m0JSON, err := json.Marshal(m0)
	c.Assert(err, gc.IsNil)
	var m1 macaroon.Macaroon
	err = json.Unmarshal(m0JSON, &m1)
	c.Assert(err, gc.IsNil)
	c.Assert(bytes.Compare(m0.Location(), m1.Location()), gc.Equals, 0)
	c.Assert(bytes.Compare(m0.Id(), m1.Id()), gc.Equals, 0)
	c.Assert(
		hex.EncodeToString(m0.Signature()),
		gc.Equals,
		hex.EncodeToString(m1.Signature()))
}

func (*macaroonSuite) TestJSONRoundTrip(c *gc.C) {
	// jsonData produced from the second example in libmacaroons
	// example README, but with the signature tweaked to
	// match our current behaviour.
	// TODO fix that behaviour so that our signatures match.
	jsonData := `{"caveats":[{"cid":"YWNjb3VudCA9IDM3MzU5Mjg1NTk="},{"cid":"dGhpcyB3YXMgaG93IHdlIHJlbWluZCBhdXRoIG9mIGtleS9wcmVk","vid":"8s3Jk17ClKmCLsv1mzMsUf0YV0J/Rku0MsD1u/snlzAT8wAQc0Dam64YsZKcUOtS1shrRXp0Jjc/FYev4kIkg3eGNKBq8FMkINAGwcA2BFHR8c7t2oc10wVksQLFeNHJ","cl":"http://auth.mybank/"}],"location":"687474703a2f2f6d7962616e6b2f","identifier":"77652075736564206f7572206f7468657220736563726574206b6579","signature":"5836a6270efd2f58410cc73e647936fb2f109f6e"}`

	var m macaroon.Macaroon
	err := json.Unmarshal([]byte(jsonData), &m)
	c.Assert(err, gc.IsNil)
	c.Assert(hex.EncodeToString(m.Signature()), gc.Equals,
		"5836a6270efd2f58410cc73e647936fb2f109f6e")
	data, err := m.MarshalJSON()
	c.Assert(err, gc.IsNil)

	// Check that the round-tripped data is the same as the original
	// data when unmarshalled into an interface{}.
	var got interface{}
	err = json.Unmarshal(data, &got)
	c.Assert(err, gc.IsNil)

	var original interface{}
	err = json.Unmarshal([]byte(jsonData), &original)
	c.Assert(err, gc.IsNil)

	c.Assert(got, gc.DeepEquals, original)
}

type caveat struct {
	rootKey   string
	location  string
	condition string
}

type macaroonSpec struct {
	rootKey  string
	id       string
	caveats  []caveat
	location string
}

func makeMacaroons(mspecs []macaroonSpec) (
	rootKey []byte,
	primary *macaroon.Macaroon,
	discharges []*macaroon.Macaroon,
) {
	var macaroons []*macaroon.Macaroon
	for _, mspec := range mspecs {
		m := MustNew([]byte(mspec.rootKey), []byte(mspec.id), []byte(mspec.location))
		for _, cav := range mspec.caveats {
			if cav.location != "" {
				err := m.AddThirdPartyCaveat([]byte(cav.rootKey), []byte(cav.condition), cav.location)
				if err != nil {
					panic(err)
				}
			} else {
				m.AddFirstPartyCaveat([]byte(cav.condition))
			}
		}
		macaroons = append(macaroons, m)
	}
	primary = macaroons[0]
	discharges = macaroons[1:]
	for _, m := range discharges {
		m.Bind(primary.Signature())
	}
	return []byte(mspecs[0].rootKey), primary, discharges
}

func assertEqualMacaroons(c *gc.C, m0, m1 *macaroon.Macaroon) {
	m0json, err := m0.MarshalJSON()
	c.Assert(err, gc.IsNil)
	m1json, err := m1.MarshalJSON()
	var m0val, m1val interface{}
	err = json.Unmarshal(m0json, &m0val)
	c.Assert(err, gc.IsNil)
	err = json.Unmarshal(m1json, &m1val)
	c.Assert(err, gc.IsNil)
	c.Assert(m0val, gc.DeepEquals, m1val)
}

func (*macaroonSuite) TestBinaryRoundTrip(c *gc.C) {
	// Test the binary marshalling and unmarshalling of a macaroon with
	// first and third party caveats.
	rootKey := []byte("secret")
	m0 := MustNew(rootKey, []byte("some id"), []byte("a location"))
	err := m0.AddFirstPartyCaveat([]byte("first caveat"))
	c.Assert(err, gc.IsNil)
	err = m0.AddFirstPartyCaveat([]byte("second caveat"))
	c.Assert(err, gc.IsNil)
	err = m0.AddThirdPartyCaveat([]byte("shared root key"), []byte("3rd party caveat"), "remote.com")
	c.Assert(err, gc.IsNil)
	data, err := m0.MarshalBinary()
	c.Assert(err, gc.IsNil)
	var m1 macaroon.Macaroon
	err = m1.UnmarshalBinary(data)
	c.Assert(err, gc.IsNil)
	assertEqualMacaroons(c, m0, &m1)
}

func (*macaroonSuite) TestMacaroonFieldsTooBig(c *gc.C) {
	rootKey := []byte("secret")
	toobig := make([]byte, macaroon.MaxPacketLen)
	_, err := rand.Reader.Read(toobig)
	c.Assert(err, gc.IsNil)
	_, err = macaroon.New(rootKey, toobig, []byte("a location"))
	c.Assert(err, gc.ErrorMatches, "macaroon identifier too big")
	_, err = macaroon.New(rootKey, []byte("some id"), toobig)
	c.Assert(err, gc.ErrorMatches, "macaroon location too big")

	m0 := MustNew(rootKey, []byte("some id"), []byte("a location"))
	err = m0.AddThirdPartyCaveat(toobig, []byte("3rd party caveat"), "remote.com")
	c.Assert(err, gc.ErrorMatches, "caveat verification id too big")
	err = m0.AddThirdPartyCaveat([]byte("shared root key"), toobig, "remote.com")
	c.Assert(err, gc.ErrorMatches, "caveat identifier too big")
	err = m0.AddThirdPartyCaveat([]byte("shared root key"), []byte("3rd party caveat"), string(toobig))
	c.Assert(err, gc.ErrorMatches, "caveat location too big")
}
