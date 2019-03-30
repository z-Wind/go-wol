package magicPacket

////////////////////////////////////////////////////////////////////////////////

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"regexp"

	"github.com/pkg/errors"
)

////////////////////////////////////////////////////////////////////////////////

var (
	delims = ":-"
	reMAC  = regexp.MustCompile(`^([0-9a-fA-F]{2}[` + delims + `]){5}([0-9a-fA-F]{2})$`)
)

////////////////////////////////////////////////////////////////////////////////

// MACAddress represents a 6 byte network mac address.
type MACAddress [6]byte

// A MagicPacket is constituted of 6 bytes of 0xFF followed by 16-groups of the
// destination MAC address.
type MagicPacket struct {
	header  [6]byte
	payload [16]MACAddress
}

// New returns a magic packet based on a mac address string.
func New(mac string) (*MagicPacket, error) {
	var packet MagicPacket
	var macAddr MACAddress

	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		return nil, errors.Wrap(err, "net.ParseMAC")
	}

	// We only support 6 byte MAC addresses since it is much harder to use the
	// binary.Write(...) interface when the size of the MagicPacket is dynamic.
	if !reMAC.MatchString(mac) {
		return nil, errors.Errorf("%s is not a IEEE 802 MAC-48 address", mac)
	}

	// Copy bytes from the returned HardwareAddr -> a fixed size MACAddress.
	for idx := range macAddr {
		macAddr[idx] = hwAddr[idx]
	}

	// Setup the header which is 6 repetitions of 0xFF.
	for idx := range packet.header {
		packet.header[idx] = 0xFF
	}

	// Setup the payload which is 16 repetitions of the MAC addr.
	for idx := range packet.payload {
		packet.payload[idx] = macAddr
	}

	return &packet, nil
}

// Marshal serializes the magic packet structure into a 102 byte slice.
func (mp *MagicPacket) marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, mp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Send MagicPacket
func (mp *MagicPacket) Send(ip string, port int) error {
	bcastAddr := fmt.Sprintf("%s:%d", ip, port)
	udpAddr, err := net.ResolveUDPAddr("udp", bcastAddr)
	if err != nil {
		return errors.Wrap(err, "net.ResolveUDPAddr")
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return errors.Wrap(err, "net.DialUDP")
	}
	defer conn.Close()

	log.Printf("Attempting to send a magic packet to MAC %x\n", mp.payload[0])
	log.Printf("... Broadcasting to: %s\n", bcastAddr)

	bs, err := mp.marshal()
	if err != nil {
		return errors.Wrap(err, "mp.marshal")
	}

	_, err = conn.Write(bs)
	return errors.Wrap(err, "conn.Write")
}
