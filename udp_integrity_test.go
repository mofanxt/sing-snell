package snell_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type handler struct{ result chan []byte }

func (h handler) NewConnectionEx(ctx context.Context, c net.Conn, s, d M.Socksaddr, close N.CloseHandlerFunc) {
	c.Close()
}

type returnHandler struct {
	payload []byte
	result  chan error
}

func (h returnHandler) NewConnectionEx(ctx context.Context, c net.Conn, s, d M.Socksaddr, onClose N.CloseHandlerFunc) {
	c.Close()
}
func (h returnHandler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, s, d M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer c.Close()
	b := buf.NewPacket()
	defer b.Release()
	if _, err := c.ReadPacket(b); err != nil {
		h.result <- err
		return
	}
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		h.result <- err
		return
	}
	defer u.Close()
	u.SetReadDeadline(time.Now().Add(time.Second))
	sender, err := net.Dial("udp4", u.LocalAddr().String())
	if err != nil {
		h.result <- err
		return
	}
	defer sender.Close()
	if _, err = sender.Write(h.payload); err != nil {
		h.result <- err
		return
	}
	source := bufio.NewPacketConn(u)
	_, err = bufio.CopyPacketWithPool(source, c, source, nil, nil, false)
	h.result <- err
}

func TestUDPReplyIntegrity(t *testing.T) {
	for _, size := range []int{1200, 1350, 1403, 1500, 2000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			key := make([]byte, 32)
			rand.Read(key)
			payload := make([]byte, size)
			rand.Read(payload)
			h := returnHandler{payload: payload, result: make(chan error, 1)}
			svc, err := snellv5.NewService(snellv5.ServiceOptions{PSK: key, Handler: h})
			if err != nil {
				t.Fatal(err)
			}
			client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: key})
			if err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(3 * time.Second))
			b.SetDeadline(time.Now().Add(3 * time.Second))
			go svc.NewConnection(context.Background(), a, M.Socksaddr{}, func(error) {})
			pc, err := client.DialPacketConn(b)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			request := buf.NewSize(1024)
			request.Resize(512, 0)
			request.WriteByte(1)
			if err = pc.WritePacket(request, M.ParseSocksaddr("127.0.0.1:443")); err != nil {
				t.Fatal(err)
			}
			response := buf.NewPacket()
			defer response.Release()
			if _, err = pc.ReadPacket(response); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, response.Bytes()) {
				t.Fatalf("回包被截断: want=%d got=%d", size, response.Len())
			}
		})
	}
}

func TestUDPOversizeRejected(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	svc, _ := snellv5.NewService(snellv5.ServiceOptions{PSK: key, Handler: handler{make(chan []byte, 1)}})
	client, _ := snellv4.NewClient(snellv4.ClientOptions{PSK: key})
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	go svc.NewConnection(context.Background(), a, M.Socksaddr{}, func(error) {})
	pc, _ := client.DialPacketConn(b)
	defer pc.Close()
	payload := buf.NewSize(19000)
	payload.Resize(512, 0)
	payload.Extend(18000)
	if err := pc.WritePacket(payload, M.ParseSocksaddr("127.0.0.1:443")); !errors.Is(err, snell.ErrPayloadTooLarge) {
		t.Fatalf("超限报文必须明确报错: %v", err)
	}
}
func (h handler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, s, d M.Socksaddr, close N.CloseHandlerFunc) {
	defer c.Close()
	b := buf.NewPacket()
	defer b.Release()
	_, err := c.ReadPacket(b)
	if err != nil {
		h.result <- nil
		return
	}
	h.result <- append([]byte(nil), b.Bytes()...)
}
func run(size int) map[string]any {
	key := make([]byte, 32)
	rand.Read(key)
	result := make(chan []byte, 1)
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: key, Handler: handler{result}})
	if err != nil {
		panic(err)
	}
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: key})
	if err != nil {
		panic(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	go service.NewConnection(context.Background(), a, M.Socksaddr{}, func(error) {})
	pc, err := client.DialPacketConn(b)
	if err != nil {
		panic(err)
	}
	defer pc.Close()
	payload := make([]byte, size)
	rand.Read(payload)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer udp.Close()
	udp.SetReadDeadline(time.Now().Add(time.Second))
	sender, err := net.Dial("udp4", udp.LocalAddr().String())
	if err != nil {
		panic(err)
	}
	defer sender.Close()
	sender.Write(payload)
	source := bufio.NewPacketConn(udp)
	go bufio.CopyPacketWithPool(source, pc, source, nil, nil, false)
	select {
	case received := <-result:
		return map[string]any{"input": size, "writer_mtu": N.CalculateMTU(nil, pc), "received": len(received), "equal": bytes.Equal(payload, received), "prefix_equal": bytes.HasPrefix(payload, received)}
	case <-time.After(4 * time.Second):
		return map[string]any{"input": size, "error": "timeout"}
	}
}
func TestUDPPacketIntegrity(t *testing.T) {
	for _, size := range []int{1000, 1162, 1200, 1350, 1400, 1500, 2000} {
		result := run(size)
		if result["equal"] != true {
			t.Fatalf("完整UDP转发失败: %v", result)
		}
	}
}
