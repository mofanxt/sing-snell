package snell

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// CommandConnectFingerprint 仅用于显式启用的私有v6扩展，不向标准端点发送。
const CommandConnectFingerprint = 0x7f

// TCPFingerprint 只保留可重建的IPv4 SYN特征，时间戳数值在采集时清零。
type TCPFingerprint struct {
	TTL      byte
	Window   uint16
	ZeroIPID bool
	Options  []byte
}

func (f *TCPFingerprint) Clone() *TCPFingerprint {
	if f == nil {
		return nil
	}
	g := *f
	g.Options = append([]byte(nil), f.Options...)
	return &g
}

func (f *TCPFingerprint) Validate() error {
	if f == nil || f.Window == 0 || len(f.Options) > 40 || len(f.Options)%4 != 0 {
		return fmt.Errorf("snell: invalid TCP fingerprint size or window")
	}
	if f.TTL != 32 && f.TTL != 64 && f.TTL != 128 && f.TTL != 255 {
		return fmt.Errorf("snell: invalid initial TTL")
	}
	seen := map[byte]bool{}
	for i := 0; i < len(f.Options); {
		k := f.Options[i]
		if k == 0 {
			for _, b := range f.Options[i:] {
				if b != 0 {
					return fmt.Errorf("snell: nonzero option padding")
				}
			}
			break
		}
		if k == 1 {
			i++
			continue
		}
		n := map[byte]int{2: 4, 3: 3, 4: 2, 8: 10}[k]
		if n == 0 || seen[k] || i+n > len(f.Options) || int(f.Options[i+1]) != n {
			return fmt.Errorf("snell: unsupported or malformed TCP option")
		}
		seen[k] = true
		if k == 2 && binary.BigEndian.Uint16(f.Options[i+2:]) < 536 {
			return fmt.Errorf("snell: invalid MSS")
		}
		if k == 3 && f.Options[i+2] > 14 {
			return fmt.Errorf("snell: invalid window scale")
		}
		if k == 8 {
			for _, b := range f.Options[i+2 : i+10] {
				if b != 0 {
					return fmt.Errorf("snell: timestamp must be normalized")
				}
			}
		}
		i += n
	}
	if !seen[2] {
		return fmt.Errorf("snell: missing MSS")
	}
	return nil
}

func (f *TCPFingerprint) MarshalBinary() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 6+len(f.Options))
	b[0], b[1] = 1, f.TTL
	if f.ZeroIPID {
		b[2] = 1
	}
	binary.BigEndian.PutUint16(b[3:5], f.Window)
	b[5] = byte(len(f.Options))
	copy(b[6:], f.Options)
	return b, nil
}

func ParseTCPFingerprint(b []byte) (*TCPFingerprint, error) {
	if len(b) < 6 || len(b) > 46 || b[0] != 1 || b[2] > 1 || int(b[5]) != len(b)-6 {
		return nil, fmt.Errorf("snell: unsupported or malformed TCP fingerprint")
	}
	f := &TCPFingerprint{TTL: b[1], ZeroIPID: b[2] == 1, Window: binary.BigEndian.Uint16(b[3:5]), Options: append([]byte(nil), b[6:]...)}
	return f, f.Validate()
}

func WriteTCPFingerprint(w io.Writer, f *TCPFingerprint) error {
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	data := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(data, uint16(len(b)))
	copy(data[2:], b)
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func ReadTCPFingerprint(r io.Reader) (*TCPFingerprint, error) {
	var length [2]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < 6 || n > 46 {
		return nil, fmt.Errorf("snell: TCP fingerprint length out of bounds")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return ParseTCPFingerprint(b)
}

type tcpFingerprintKey struct{}

func ContextWithTCPFingerprint(ctx context.Context, f *TCPFingerprint) context.Context {
	return context.WithValue(ctx, tcpFingerprintKey{}, f.Clone())
}

func TCPFingerprintFromContext(ctx context.Context) *TCPFingerprint {
	f, _ := ctx.Value(tcpFingerprintKey{}).(*TCPFingerprint)
	return f.Clone()
}
