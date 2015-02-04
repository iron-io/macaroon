package macaroon

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

type field byte

// field names, as defined in libmacaroons
const (
	fieldInvalid field = iota
	fieldLocation
	fieldIdentifier
	fieldSignature
	fieldCaveat
	fieldVerificationId
)

var fieldStrings = [...]string{
	fieldInvalid:        "invalid",
	fieldLocation:       "location",
	fieldIdentifier:     "identifier",
	fieldSignature:      "signature",
	fieldCaveat:         "cav",
	fieldVerificationId: "vid",
}

func (f field) String() string {
	if int(f) >= len(fieldStrings) {
		f = fieldInvalid
	}
	return fieldStrings[f]
}

// macaroonJSON defines the JSON format for macaroons.
type macaroonJSON struct {
	Caveats    string `json:"caveats"`
	Location   string `json:"location"`
	Identifier string `json:"identifier"`
	Signature  string `json:"signature"` // hex-encoded
}

// caveatJSON defines the JSON format for caveats within a macaroon.
type caveatJSON struct {
	CID      string `json:"cid"`
	VID      string `json:"vid,omitempty"`
	Location string `json:"cl,omitempty"`
}

// MarshalJSON implements json.Marshaler.
func (m *Macaroon) MarshalJSON() ([]byte, error) {
	mjson := macaroonJSON{
		Location:   m.Location(),
		Identifier: m.dataStr(m.id),
		Signature:  hex.EncodeToString(m.sig),
		Caveats:    hex.EncodeToString(m.caveatsRaw()),
	}
	data, err := json.Marshal(mjson)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal json data: %v", err)
	}
	return data, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (m *Macaroon) UnmarshalJSON(jsonData []byte) error {
	var mjson macaroonJSON
	var ok bool
	err := json.Unmarshal(jsonData, &mjson)
	if err != nil {
		return fmt.Errorf("cannot unmarshal json data: %v", err)
	}
	if err := m.init(mjson.Identifier, mjson.Location); err != nil {
		return err
	}
	m.sig, err = hex.DecodeString(mjson.Signature)
	if err != nil {
		return fmt.Errorf("cannot decode macaroon signature %q: %v", m.sig, err)
	}
	cavData, err := hex.DecodeString(mjson.Caveats)
	if err != nil {
		return fmt.Errorf("cannot decode macaroon caveats %q: %v", m.caveats, err)
	}
	m.caveats, ok = m.appendPacket(fieldCaveat, cavData)
	if !ok {
		return fmt.Errorf("cannot decode macaroon caveats")
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (m *Macaroon) MarshalBinary() ([]byte, error) {
	data := make([]byte, 0, m.marshalBinaryLen())
	return m.appendBinary(data)
}

// The binary format of a macaroon is as follows.
// Each identifier repesents a packet.
//
// location
// identifier
// (
//	caveatId?
//	verificationId?
//	caveatLocation?
// )*
// signature

// unmarshalBinaryNoCopy is the internal implementation of
// UnmarshalBinary. It differs in that it does not copy the
// data.
func (m *Macaroon) unmarshalBinaryNoCopy(data []byte) error {
	m.data = data
	var err error
	var start int

	start, m.location, err = m.expectPacket(0, fieldLocation)
	if err != nil {
		return err
	}
	start, m.id, err = m.expectPacket(start, fieldIdentifier)
	if err != nil {
		return err
	}
	start, m.caveats, err = m.expectPacket(start, fieldCaveat)
	if err != nil {
		return err
	}

	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (m *Macaroon) UnmarshalBinary(data []byte) error {
	data = append([]byte(nil), data...)
	return m.unmarshalBinaryNoCopy(data)
}

func (m *Macaroon) expectPacket(start int, kind field) (int, packet, error) {
	p, err := m.parsePacket(start)
	if err != nil {
		return 0, packet{}, err
	}
	if f := m.fieldNum(p); f != kind {
		return 0, packet{}, fmt.Errorf("unexpected field %v; expected %s", f, kind)
	}
	return start + p.len(), p, nil
}

func (m *Macaroon) appendBinary(data []byte) ([]byte, error) {
	data = append(data, m.data...)
	data, _, ok := rawAppendPacket(data, fieldSignature, m.sig)
	if !ok {
		return nil, fmt.Errorf("failed to append signature to macaroon, packet is too long")
	}
	return data, nil
}

func (m *Macaroon) marshalBinaryLen() int {
	return len(m.data) + packetSize(m.sig)
}

// Slice defines a collection of macaroons. By convention, the
// first macaroon in the slice is a primary macaroon and the rest
// are discharges for its third party caveats.
type Slice []*Macaroon

// MarshalBinary implements encoding.BinaryMarshaler.
func (s Slice) MarshalBinary() ([]byte, error) {
	size := 0
	for _, m := range s {
		size += m.marshalBinaryLen()
	}
	data := make([]byte, 0, size)
	var err error
	for _, m := range s {
		data, err = m.appendBinary(data)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal macaroon %q: %v", m.Id(), err)
		}
	}
	return data, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *Slice) UnmarshalBinary(data []byte) error {
	data = append([]byte(nil), data...)
	*s = (*s)[:0]
	for len(data) > 0 {
		var m Macaroon
		err := m.unmarshalBinaryNoCopy(data)
		if err != nil {
			return fmt.Errorf("cannot unmarshal macaroon: %v", err)
		}
		*s = append(*s, &m)
		// Prevent the macaroon from overwriting the other ones
		// by setting the capacity of its data.
		m.data = m.data[0:len(m.data):m.marshalBinaryLen()]
		data = data[m.marshalBinaryLen():]
	}
	return nil
}

// convert data struct into []byte
func MarshalCaveats(v interface{}) ([]byte, error) {
	obj := reflect.ValueOf(v)

	var out bytes.Buffer

	for i := 0; i < obj.NumField(); i += 1 {
		val := obj.Field(i)

		switch val.Kind() {
		case reflect.Ptr:
			if val.IsNil() {
				// ignore
			} else {
				data, err := valToBytes(val.Elem())
				if err != nil {
					return []byte{}, err
				}

				out.Write([]byte{byte(uint8(i))})  // Field Num
				out.Write([]byte{byte(len(data))}) // Field Size
				out.Write(data)                    // Field data itself
			}
		default:
			panic("non-pointer type, please check structure field types")
		}

	}

	return out.Bytes(), nil
}

func UnMarshalCaveats(v interface{}, data []byte) error {
	dataLen := len(data)

	obj := reflect.ValueOf(v).Elem()
	typeOfStruct := obj.Type()

	cursor := 0
	for cursor < dataLen {
		fieldNum := uint8(data[cursor])
		dataSize := uint8(data[cursor+1])

		fieldData := data[cursor+2 : cursor+2+int(dataSize)]

		t := typeOfStruct.Field(int(fieldNum)).Type

		val := obj.Field(int(fieldNum))

		value, err := bytesToVal(t, fieldData)

		if err != nil {
			return err
		}

		val.Set(value)

		cursor += 2 + int(dataSize)
	}
	return nil
}

func valToBytes(val reflect.Value) ([]byte, error) {
	switch val.Kind() {
	case reflect.Int, reflect.Uint:
		panic("please always specify exact size, like int8 or uint32")

	case reflect.Slice:
		return val.Bytes(), nil

	case reflect.String:
		return []byte(val.String()), nil

	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buf := new(bytes.Buffer)
		var err error

		// TODO: refactor somehow
		switch val.Kind() {
		case reflect.Int8:
			err = binary.Write(buf, binary.LittleEndian, int8(val.Int()))
		case reflect.Int16:
			err = binary.Write(buf, binary.LittleEndian, int16(val.Int()))
		case reflect.Int32:
			err = binary.Write(buf, binary.LittleEndian, int32(val.Int()))
		case reflect.Int64:
			err = binary.Write(buf, binary.LittleEndian, val.Int())
		case reflect.Uint8:
			err = binary.Write(buf, binary.LittleEndian, uint8(val.Uint()))
		case reflect.Uint16:
			err = binary.Write(buf, binary.LittleEndian, uint16(val.Uint()))
		case reflect.Uint32:
			err = binary.Write(buf, binary.LittleEndian, uint32(val.Uint()))
		case reflect.Uint64:
			err = binary.Write(buf, binary.LittleEndian, val.Uint())
		default:
			panic("bug in the code")
		}
		return buf.Bytes(), err

	case reflect.Bool:
		value := val.Bool()
		if value {
			return []byte{1}, nil
		} else {
			return []byte{0}, nil
		}
	default:
		panic("Unsupported type, please check structure field types")
	}

	var data []byte
	data = make([]byte, 5, 5)

	return data, nil
}

func bytesToVal(val reflect.Type, data []byte) (reflect.Value, error) {
	var err error

	switch val.Elem().Kind() {
	case reflect.Int, reflect.Uint:
		panic("please always specify exact size, like int8 or uint32")

	case reflect.Slice:
		return reflect.ValueOf(&data), nil

	case reflect.String:
		str := string(data)
		return reflect.ValueOf(&str), nil

	case reflect.Bool:
		var value bool
		if data[0] == 1 {
			value = true
		} else if data[0] == 0 {
			value = false
		} else {
			err = errors.New("can not decode input data")
		}
		return reflect.ValueOf(&value), err

	// TODO: refactor somehow
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		buf := bytes.NewReader(data)
		switch val.Elem().Kind() {
		case reflect.Int8:
			var n int8
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Int16:
			var n int16
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Int32:
			var n int32
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Int64:
			var n int64
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Uint8:
			var n uint8
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Uint16:
			var n uint16
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Uint32:
			var n uint32
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		case reflect.Uint64:
			var n uint64
			err = binary.Read(buf, binary.LittleEndian, &n)
			return reflect.ValueOf(&n), err
		default:
			panic("bug in the code")
		}

	default:
		return reflect.ValueOf(nil), errors.New("unknown field type")
	}
}
