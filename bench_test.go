package macaroon_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/iron-io/macaroon"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func BenchmarkNew(b *testing.B) {
	rootKey := randomBytes(24)
	id := base64.StdEncoding.EncodeToString(randomBytes(100))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		MustNew(rootKey, id, loc)
	}
}

func BenchmarkAddCaveat(b *testing.B) {
	rootKey := randomBytes(24)
	id := base64.StdEncoding.EncodeToString(randomBytes(100))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		b.StopTimer()
		m := MustNew(rootKey, id, loc)
		b.StartTimer()
		m.AddFirstPartyCaveat("some caveat stuff")
	}
}

func benchmarkVerify(b *testing.B, mspecs []macaroonSpec) {
	rootKey, primary, discharges := makeMacaroons(mspecs)
	check := func(string) error {
		return nil
	}
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		err := primary.Verify(rootKey, check, discharges)
		if err != nil {
			b.Fatalf("verification failed: %v", err)
		}
	}
}

func BenchmarkVerifyLarge(b *testing.B) {
	benchmarkVerify(b, recursiveThirdPartyCaveatMacaroons)
}

func BenchmarkVerifySmall(b *testing.B) {
	benchmarkVerify(b, []macaroonSpec{{
		rootKey: "root-key",
		id:      "root-id",
		caveats: []caveat{{
			condition: "wonderful",
		}},
	}})
}

func BenchmarkMarshalJSON(b *testing.B) {
	rootKey := randomBytes(24)
	id := base64.StdEncoding.EncodeToString(randomBytes(100))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	m := MustNew(rootKey, id, loc)
	b.ResetTimer()
	for i := b.N - 1; i >= 0; i-- {
		_, err := m.MarshalJSON()
		if err != nil {
			b.Fatalf("cannot marshal JSON: %v", err)
		}
	}
}

func MustNew(rootKey []byte, id, loc string) *macaroon.Macaroon {
	m, err := macaroon.New(rootKey, id, loc)
	if err != nil {
		panic(err)
	}
	return m
}

func BenchmarkUnmarshalJSON(b *testing.B) {
	rootKey := randomBytes(24)
	id := base64.StdEncoding.EncodeToString(randomBytes(100))
	loc := base64.StdEncoding.EncodeToString(randomBytes(40))
	m := MustNew(rootKey, id, loc)
	data, err := m.MarshalJSON()
	if err != nil {
		b.Fatalf("cannot marshal JSON: %v", err)
	}
	for i := b.N - 1; i >= 0; i-- {
		var m macaroon.Macaroon
		err := m.UnmarshalJSON(data)
		if err != nil {
			b.Fatalf("cannot unmarshal JSON: %v", err)
		}
	}
}
