package snellv4

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// A stream may only end between records. Cutting it inside a record must not
// look like a clean end.
func TestReaderEOFInsideRecord(t *testing.T) {
	t.Parallel()
	psk := []byte("record-eof-test-psk")
	var wire bytes.Buffer
	recordWriter := &writer{upstream: &wire, psk: psk}
	_, err := recordWriter.Write([]byte("first"))
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
		recordReader := &reader{upstream: bytes.NewReader(data[:cut]), psk: psk}
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
