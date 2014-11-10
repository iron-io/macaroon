package macaroon

import (
	"encoding/binary"
	"fmt"
)

// The macaroon binary encoding is made from a sequence
// of "packets", each of which has a field name and some data.
// The encoding is:
//
// - four ascii hex digits holding the entire packet size (including
// the digits themselves).
//
// - the field name, followed by an ascii space.
//
// - the raw data
//
// For efficiency, we store all the packets inside
// a single byte slice inside the macaroon, Macaroon.data. This
// is reasonable to do because we only ever append
// to macaroons.
//
// The packet struct below holds a reference into Macaroon.data.
type packet struct {
	start     int32
	totalLen  uint16
	headerLen uint16
}

func (p packet) len() int {
	return int(p.totalLen)
}

const headerLen = 3

// dataBytes returns the data payload of the packet.
func (m *Macaroon) dataBytes(p packet) []byte {
	if p.totalLen == 0 {
		return nil
	}
	return m.data[p.start+headerLen : p.start+int32(p.totalLen)]
}

func (m *Macaroon) dataStr(p packet) string {
	return string(m.dataBytes(p))
}

// packetBytes returns the entire packet.
func (m *Macaroon) packetBytes(p packet) []byte {
	return m.data[p.start : p.start+int32(p.totalLen)]
}

// fieldName returns the field name of the packet.
func (m *Macaroon) fieldNum(p packet) field {
	if p.totalLen == 0 {
		return fieldInvalid
	}
	return field(m.data[p.start+2])
}

// parsePacket parses the packet starting at the given
// index into m.data.
func (m *Macaroon) parsePacket(start int) (packet, error) {
	data := m.data[start:]
	if len(data) < 6 {
		return packet{}, fmt.Errorf("packet too short")
	}
	plen := parseSize(data)
	if plen > len(data) {
		return packet{}, fmt.Errorf("packet size too big")
	}
	data = data[2:plen]
	return packet{
		start:    int32(start),
		totalLen: uint16(plen),
	}, nil
}

const maxPacketLen = 0xffff

// appendPacket appends a packet with the given field name
// and data to m.data, and returns the packet appended.
//
// It returns false (and a zero packet) if the packet was too big.
func (m *Macaroon) appendPacket(f field, data []byte) (packet, bool) {
	mdata, p, ok := rawAppendPacket(m.data, f, data)
	if !ok {
		return p, false
	}
	m.data = mdata
	return p, true
}

// rawAppendPacket appends a packet to the given byte slice.
func rawAppendPacket(buf []byte, f field, data []byte) ([]byte, packet, bool) {
	plen := 2 + 1 + len(data)
	if plen > maxPacketLen {
		return nil, packet{}, false
	}
	s := packet{
		start:    int32(len(buf)),
		totalLen: uint16(plen),
	}
	buf = appendSize(buf, plen)
	buf = append(buf, byte(f))
	buf = append(buf, data...)
	return buf, s, true
}

func appendSize(data []byte, size int) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(size))
	return append(data, buf[:]...)
}

func parseSize(data []byte) int {
	return int(binary.LittleEndian.Uint16(data))
}
