package test

import (
	"bytes"
	"context"
	"crypto/rand"
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

	"github.com/stretchr/testify/require"
)

type udpIntegrityHandler struct {
	handle func(N.PacketConn)
}

func (h udpIntegrityHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func (h udpIntegrityHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	h.handle(conn)
}

// Use a real TCP connection so Linux can exercise the automatic batch path.
func newUDPIntegrityPair(t *testing.T, handler udpIntegrityHandler) N.PacketConn {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: key, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: key})
	require.NoError(t, err)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	clientConn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { clientConn.Close() })
	serverConn, err := listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { serverConn.Close() })
	require.NoError(t, clientConn.SetDeadline(time.Now().Add(10*time.Second)))
	require.NoError(t, serverConn.SetDeadline(time.Now().Add(10*time.Second)))
	go service.NewConnection(context.Background(), serverConn, M.Socksaddr{}, func(error) {})
	packetConn, err := client.DialPacketConn(clientConn)
	require.NoError(t, err)
	t.Cleanup(func() { packetConn.Close() })
	return packetConn
}

func udpIntegritySource(t *testing.T, payload []byte) N.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	sender, err := net.Dial("udp4", conn.LocalAddr().String())
	require.NoError(t, err)
	defer sender.Close()
	_, err = sender.Write(payload)
	require.NoError(t, err)
	return bufio.NewPacketConn(conn)
}

func copyUDPIntegrity(source, destination N.PacketConn, batch bool) error {
	if batch {
		_, err := bufio.CopyPacket(destination, source)
		return err
	}
	_, err := bufio.CopyPacketWithPool(source, destination, source, nil, nil, false)
	return err
}

func TestV4UDPCopyPreservesDatagrams(t *testing.T) {
	for _, batch := range []bool{false, true} {
		for _, size := range []int{1000, 1162, 1200, 1350, 1400, 1500, 2000, 4000, 8000} {
			t.Run(fmt.Sprintf("batch=%t/size=%d", batch, size), func(t *testing.T) {
				payload := make([]byte, size)
				rand.Read(payload)
				received := make(chan []byte, 1)
				packetConn := newUDPIntegrityPair(t, udpIntegrityHandler{handle: func(conn N.PacketConn) {
					buffer := buf.NewPacket()
					defer buffer.Release()
					_, err := conn.ReadPacket(buffer)
					if err != nil {
						received <- nil
						return
					}
					received <- bytes.Clone(buffer.Bytes())
				}})
				source := udpIntegritySource(t, payload)
				done := make(chan error, 1)
				go func() { done <- copyUDPIntegrity(source, packetConn, batch) }()
				select {
				case actual := <-received:
					require.Equal(t, payload, actual, "UDP datagram was truncated")
				case <-time.After(10 * time.Second):
					t.Fatal("timed out waiting for the complete datagram")
				}
				source.Close()
				packetConn.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("packet copy did not stop")
				}
			})
		}
	}
}

func TestV5UDPReplyCopyPreservesDatagrams(t *testing.T) {
	for _, batch := range []bool{false, true} {
		for _, size := range []int{1200, 1350, 1403, 1500, 2000, 4000, 8000} {
			t.Run(fmt.Sprintf("batch=%t/size=%d", batch, size), func(t *testing.T) {
				payload := make([]byte, size)
				rand.Read(payload)
				source := udpIntegritySource(t, payload)
				done := make(chan error, 1)
				packetConn := newUDPIntegrityPair(t, udpIntegrityHandler{handle: func(conn N.PacketConn) {
					request := buf.NewPacket()
					defer request.Release()
					_, err := conn.ReadPacket(request)
					if err != nil {
						done <- err
						return
					}
					done <- copyUDPIntegrity(source, conn, batch)
				}})
				request := buf.NewSize(1024)
				request.Resize(512, 0)
				request.WriteByte(1)
				require.NoError(t, packetConn.WritePacket(request, M.ParseSocksaddr("127.0.0.1:443")))
				response := buf.NewPacket()
				defer response.Release()
				_, err := packetConn.ReadPacket(response)
				require.NoError(t, err)
				require.Equal(t, payload, response.Bytes(), "UDP reply was truncated")
				source.Close()
				packetConn.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("packet copy did not stop")
				}
			})
		}
	}
}

func TestV4UDPOversizeStillRejected(t *testing.T) {
	packetConn := newUDPIntegrityPair(t, udpIntegrityHandler{handle: func(conn N.PacketConn) {
		buffer := buf.NewPacket()
		defer buffer.Release()
		conn.ReadPacket(buffer)
	}})
	payload := buf.NewSize(19000)
	payload.Resize(512, 0)
	payload.Extend(18000)
	err := packetConn.WritePacket(payload, M.ParseSocksaddr("127.0.0.1:443"))
	require.ErrorIs(t, err, snell.ErrPayloadTooLarge)
}
