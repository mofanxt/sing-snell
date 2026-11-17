package snell_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func sampleFingerprint(w uint16) *snell.TCPFingerprint {
	return &snell.TCPFingerprint{TTL: 64, Window: w, ZeroIPID: true, Options: []byte{2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 0, 0}}
}

func TestFingerprintEncoding(t *testing.T) {
	f := sampleFingerprint(65535)
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	g, err := snell.ParseTCPFingerprint(b)
	if err != nil || !reflect.DeepEqual(f, g) {
		t.Fatalf("roundtrip: %v %v", g, err)
	}
	for i := 0; i < len(b); i++ {
		if _, err = snell.ParseTCPFingerprint(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	for _, bad := range [][]byte{append([]byte{2}, b[1:]...), append(append([]byte{}, b...), 0), {1, 64, 0, 0, 1, 0}} {
		if _, err = snell.ParseTCPFingerprint(bad); err == nil {
			t.Fatalf("accepted invalid %x", bad)
		}
	}
	f.Options[8] = 30
	if f.Validate() == nil {
		t.Fatal("accepted unknown option")
	}
	f = sampleFingerprint(65535)
	f.Options[7] = 15
	if f.Validate() == nil {
		t.Fatal("accepted invalid scale")
	}
	f = sampleFingerprint(65535)
	f.Options[12] = 1
	if f.Validate() == nil {
		t.Fatal("accepted raw timestamp")
	}
	if err = snell.WriteTCPFingerprint(io.Discard, nil); err == nil {
		t.Fatal("accepted nil")
	}
	if _, err = snell.ReadTCPFingerprint(bytes.NewReader([]byte{255, 255})); err == nil {
		t.Fatal("accepted excessive length")
	}
}

func TestLegacyRequestUnchanged(t *testing.T) {
	r := snell.Request{Command: snell.CommandConnectV2, Destination: M.ParseSocksaddr("example.com:443")}
	b := buf.NewSize(r.Len())
	defer b.Release()
	if err := r.Write(b); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{1, 5, 0, 11}, []byte("example.com")...)
	want = append(want, 1, 187)
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatalf("legacy changed: %x", b.Bytes())
	}
}

type fpHandler struct{ seen chan *snell.TCPFingerprint }

func (h fpHandler) NewConnectionEx(ctx context.Context, c net.Conn, _ M.Socksaddr, _ M.Socksaddr, done N.CloseHandlerFunc) {
	h.seen <- snell.TCPFingerprintFromContext(ctx)
	go func() {
		_, err := io.Copy(c, c)
		if closeErr := N.CloseWrite(c); err == nil {
			err = closeErr
		}
		c.Close()
		if done != nil {
			done(err)
		}
	}()
}
func (h fpHandler) NewPacketConnectionEx(_ context.Context, c N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, done N.CloseHandlerFunc) {
	c.Close()
	if done != nil {
		done(nil)
	}
}

type fpDialer struct {
	N.Dialer
	count atomic.Int32
}

func (d *fpDialer) DialContext(ctx context.Context, n string, a M.Socksaddr) (net.Conn, error) {
	d.count.Add(1)
	return d.Dialer.DialContext(ctx, n, a)
}

func TestFingerprintPerLogicalConnection(t *testing.T) {
	for _, reuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "reuse"}[reuse], func(t *testing.T) {
			h := fpHandler{make(chan *snell.TCPFingerprint, 16)}
			s, err := snellv6.NewMultiService[int](snellv6.ServerOptions{PSK: []byte("test-fingerprint-key-1234"), Handler: h, Fingerprint: true})
			if err != nil {
				t.Fatal(err)
			}
			if err = s.UpdateUsers([]int{1}, [][]byte{[]byte("test-user")}); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			go func() {
				for {
					c, e := l.Accept()
					if e != nil {
						return
					}
					go s.NewConnection(context.Background(), c, M.SocksaddrFromNet(c.RemoteAddr()), nil)
				}
			}()
			d := &fpDialer{Dialer: N.SystemDialer}
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("test-fingerprint-key-1234"), UserKey: []byte("test-user"), Server: M.ParseSocksaddr(l.Addr().String()), Dialer: d, Reuse: reuse, Fingerprint: true})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, f := range []*snell.TCPFingerprint{sampleFingerprint(65535), nil, sampleFingerprint(32768), nil} {
				ctx := snell.ContextWithTCPFingerprint(context.Background(), f)
				c, e := client.DialContext(ctx, M.ParseSocksaddr("example.com:443"))
				if e != nil {
					t.Fatal(e)
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, e = c.Write([]byte("tls-payload-unchanged")); e != nil {
					t.Fatal(e)
				}
				if e = N.CloseWrite(c); e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(c)
				if e != nil {
					t.Fatal(e)
				}
				if string(b) != "tls-payload-unchanged" {
					t.Fatal("payload changed")
				}
				select {
				case got := <-h.seen:
					if !reflect.DeepEqual(got, f) {
						t.Fatalf("metadata leaked: got=%v want=%v", got, f)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("no metadata")
				}
				c.Close()
				time.Sleep(20 * time.Millisecond)
			}
			if reuse && d.count.Load() != 1 {
				t.Fatalf("reuse not exercised: dials=%d", d.count.Load())
			}
		})
	}
}

func FuzzTCPFingerprint(f *testing.F) {
	b, _ := sampleFingerprint(65535).MarshalBinary()
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := snell.ParseTCPFingerprint(b)
		if err == nil {
			out, e := v.MarshalBinary()
			if e != nil || !bytes.Equal(b, out) {
				t.Fatal("noncanonical fingerprint")
			}
		}
	})
}
