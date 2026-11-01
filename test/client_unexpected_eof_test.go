package test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

// abruptCloseHandler sends part of a response and then closes the TCP write
// side without a zero chunk, like a crashed server or a middlebox FIN.
type abruptCloseHandler struct{ localEchoHandler }

func (abruptCloseHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		_, err := conn.Write([]byte("partial"))
		if err != nil {
			return
		}
		var upstream any = conn
		for {
			if tcpConn, isTCP := upstream.(*net.TCPConn); isTCP {
				tcpConn.CloseWrite()
				break
			}
			wrapper, isWrapper := upstream.(interface{ Upstream() any })
			if !isWrapper {
				return
			}
			upstream = wrapper.Upstream()
		}
		time.Sleep(time.Second)
	}()
}

func testClientUnexpectedEOF(t *testing.T, service snell.Service, newClient func(server M.Socksaddr, reuse bool) eofTestDialer) {
	for _, reuse := range []bool{false, true} {
		name := "plain"
		if reuse {
			name = "reuse"
		}
		t.Run(name, func(t *testing.T) {
			serviceAddress := startLocalSnellService(t, service)
			var proxy countingTCPProxy
			proxy.Start(t, serviceAddress)
			client := newClient(M.ParseSocksaddr(proxy.address), reuse)
			defer client.Close()
			destination := M.ParseSocksaddrHostPort("127.0.0.1", 443)

			for round := 1; round <= 2; round++ {
				conn, err := client.DialContext(context.Background(), destination)
				require.NoError(t, err)
				_, err = conn.Write([]byte("request"))
				require.NoError(t, err)
				require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
				data, err := io.ReadAll(conn)
				conn.Close()
				require.Equal(t, "partial", string(data))
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
				// A session that ended without a zero chunk must not be reused.
				require.EqualValues(t, round, proxy.count.Load())
			}
		})
	}
}

func TestV4ClientUnexpectedEOF(t *testing.T) {
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: abruptCloseHandler{}})
	require.NoError(t, err)
	testClientUnexpectedEOF(t, service, func(server M.Socksaddr, reuse bool) eofTestDialer {
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), Reuse: reuse, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

func TestV6ClientUnexpectedEOF(t *testing.T) {
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Handler: abruptCloseHandler{}})
	require.NoError(t, err)
	testClientUnexpectedEOF(t, service, func(server M.Socksaddr, reuse bool) eofTestDialer {
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Reuse: reuse, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

type eofTestDialer interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}
