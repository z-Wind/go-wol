package magicPacket

import (
	"testing"
)

func TestSendUDP(t *testing.T) {
	mp, err := New("11:22:33:44:55:66")
	if err != nil {
		t.Error(err)
	}
	err = mp.SendUDP("192.168.1.255", 9)
	if err != nil {
		t.Error(err)
	}
}
