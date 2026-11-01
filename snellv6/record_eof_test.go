package snellv6

import (
	"bytes"
	"errors"
	"io"
	"testing"

	N "github.com/sagernet/sing/common/network"
)

// A stream may only end between records. Cutting it inside a record must not
// look like a clean end.
func TestReaderEOFInsideRecord(t *testing.T) {
	t.Parallel()
	psk := []byte("record-eof-test-psk")
	profile := NewProfile(psk)
	for _, mode := range []Mode{ModeDefault, ModeUnshaped, ModeUnsafeRaw} {
		var wire bytes.Buffer
		recordWriter, err := writeFirstRecord(&wire, mode, psk, profile, []byte("first"))
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
			recordReader, record, err := readFirstRecord(bytes.NewReader(data[:cut]), mode, psk, profile, N.ReadWaitOptions{})
			if err != nil {
				t.Fatalf("mode %v cut %d: first record: %v", mode, cut, err)
			}
			record.Release()
			_, err = recordReader.ReadRecord()
			want := io.ErrUnexpectedEOF
			if cut == boundary {
				want = io.EOF
			}
			if !errors.Is(err, want) {
				t.Fatalf("mode %v cut %d of %d: got %v, want %v", mode, cut, len(data), err, want)
			}
		}
	}
}
