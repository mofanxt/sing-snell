package test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type udpDomainSourceHandler struct {
	conns chan N.PacketConn
}

func (h udpDomainSourceHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}

func (h udpDomainSourceHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h.conns <- conn
}

func udpDomainSourcePayload(payload string) *buf.Buffer {
	buffer := buf.NewSize(8192)
	buffer.Resize(4096, 0)
	copy(buffer.Extend(len(payload)), payload)
	return buffer
}

// An outbound may report a domain as the reply source. The protocol carries IP
// sources only, so that reply is dropped and the session keeps working.
func testUDPDomainReplySource(t *testing.T, dial func(conn net.Conn) (N.PacketConn, error), handler udpDomainSourceHandler, serviceAddress string) {
	for _, batch := range []bool{false, true} {
		name := "single"
		if batch {
			name = "batch"
		}
		t.Run(name, func(t *testing.T) {
			tcpConn, err := net.DialTimeout("tcp", serviceAddress, time.Second)
			require.NoError(t, err)
			defer tcpConn.Close()
			require.NoError(t, tcpConn.SetDeadline(time.Now().Add(10*time.Second)))
			packetConn, err := dial(tcpConn)
			require.NoError(t, err)
			defer packetConn.Close()

			domain := M.ParseSocksaddrHostPort("example.com", 443)
			require.NoError(t, packetConn.WritePacket(udpDomainSourcePayload("request"), domain))
			serverConn := <-handler.conns
			defer serverConn.Close()
			request := buf.NewPacket()
			destination, err := serverConn.ReadPacket(request)
			request.Release()
			require.NoError(t, err)
			require.Equal(t, domain, destination)

			ipSource := M.ParseSocksaddrHostPort("203.0.113.1", 443)
			if batch {
				// The service hands over the conn wrapped with the cached first packet.
				writer, created := serverConn.(interface{ Upstream() any }).Upstream().(interface {
					CreatePacketBatchWriter() (N.PacketBatchWriter, bool)
				}).CreatePacketBatchWriter()
				require.True(t, created)
				require.NoError(t, writer.WritePacketBatch(
					[]*buf.Buffer{udpDomainSourcePayload("dropped"), udpDomainSourcePayload("kept")},
					[]M.Socksaddr{domain, ipSource},
				))
			} else {
				require.NoError(t, serverConn.WritePacket(udpDomainSourcePayload("dropped"), domain))
				require.NoError(t, serverConn.WritePacket(udpDomainSourcePayload("kept"), ipSource))
			}

			response := buf.NewPacket()
			defer response.Release()
			source, err := packetConn.ReadPacket(response)
			require.NoError(t, err)
			require.Equal(t, ipSource, source)
			require.Equal(t, "kept", string(response.Bytes()))
		})
	}
}

func TestV5UDPDomainReplySource(t *testing.T) {
	handler := udpDomainSourceHandler{conns: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK)})
	require.NoError(t, err)
	testUDPDomainReplySource(t, func(conn net.Conn) (N.PacketConn, error) {
		return client.DialPacketConn(conn)
	}, handler, startLocalSnellService(t, service))
}

func TestV6UDPDomainReplySource(t *testing.T) {
	handler := udpDomainSourceHandler{conns: make(chan N.PacketConn, 1)}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Handler: handler})
	require.NoError(t, err)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK)})
	require.NoError(t, err)
	testUDPDomainReplySource(t, func(conn net.Conn) (N.PacketConn, error) {
		packetConn, err := client.DialPacketConn(conn)
		if err != nil {
			return nil, err
		}
		return packetConn, nil
	}, handler, startLocalSnellService(t, service))
}
