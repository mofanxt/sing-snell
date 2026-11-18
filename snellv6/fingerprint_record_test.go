package snellv6

import (
	"bytes"
	"io"
	"strings"
	"testing"

	snell "github.com/mofanxt/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestFingerprintHeaderAcrossShapedRecords(t *testing.T) {
	psk := []byte("local-test-fixture-0")
	profile := NewProfile(psk)
	// 固定合法的记录上限，使扩展字段横跨首条与第二条记录。
	profile.firstRecordCap = 256
	r := snell.Request{Command: snell.CommandConnectFingerprint, ClientID: bytes.Repeat([]byte("u"), 240), Destination: M.ParseSocksaddr(strings.Repeat("a", 30) + ".example:443"), TCPFingerprint: &snell.TCPFingerprint{TTL: 64, Window: 8192, Options: []byte{2, 4, 5, 180}}}
	payload := []byte("first application bytes")
	b := buf.NewSize(r.Len() + len(payload))
	defer b.Release()
	if err := r.Write(b); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write(payload); err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	if _, err := writeFirstRecord(&wire, ModeDefault, psk, profile, b.Bytes()); err != nil {
		t.Fatal(err)
	}
	reader, record, err := readFirstRecord(&wire, ModeDefault, psk, profile, N.ReadWaitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer record.Release()
	defer reader.ReleaseCache()
	if record.Len() >= r.Len() {
		t.Fatal("fixture did not split the header")
	}
	got, err := (&Service{fingerprint: true, mode: ModeDefault}).readRequest(record, reader)
	if err != nil || got.Destination != r.Destination || !bytes.Equal(got.ClientID, r.ClientID) || got.TCPFingerprint.Window != 8192 {
		t.Fatalf("decoded request: %v %v", got, err)
	}
	rest := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, rest); err != nil || !bytes.Equal(rest, payload) {
		t.Fatalf("application data: %q %v", rest, err)
	}
}
