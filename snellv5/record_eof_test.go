package snellv5

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"testing"

	snell "github.com/sagernet/sing-snell"
)

// A stream may only end between records. Cutting it inside a record must not
// look like a clean end.
func TestReaderEOFInsideRecord(t *testing.T) {
	t.Parallel()
	newAEAD := func() cipher.AEAD {
		aead, err := snell.NewAEAD(snell.DeriveKey([]byte("record-eof-test-psk"), make([]byte, snell.SaltLen)))
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	var wire bytes.Buffer
	recordWriter, err := newWriter(&wire, newAEAD(), make([]byte, snell.NonceLen))
	if err != nil {
		t.Fatal(err)
	}
	_, err = recordWriter.Write([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	boundary := wire.Len()
	_, err = recordWriter.Write([]byte("second record payload"))
	if err != nil {
		t.Fatal(err)
	}
	data := wire.Bytes()
	for cut := boundary; cut < len(data); cut++ {
		recordReader := newReader(bytes.NewReader(data[:cut]), newAEAD(), make([]byte, snell.NonceLen))
		record, err := recordReader.ReadRecord()
		if err != nil {
			t.Fatalf("cut %d: first record: %v", cut, err)
		}
		record.Release()
		_, err = recordReader.ReadRecord()
		want := io.ErrUnexpectedEOF
		if cut == boundary {
			want = io.EOF
		}
		if !errors.Is(err, want) {
			t.Fatalf("cut %d of %d: got %v, want %v", cut, len(data), err, want)
		}
	}
}
