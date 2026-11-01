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
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type reuseDialer interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

// A write that reaches a reuse connection after Close must fail instead of
// landing on the pooled session, which the next connection may already use.
func testReuseWriteAfterClose(t *testing.T, service snell.Service, newClient func(server M.Socksaddr) reuseDialer) {
	lateWrites := map[string]func(conn net.Conn) error{
		"Write": func(conn net.Conn) error {
			_, err := conn.Write([]byte("|LATE"))
			return err
		},
		"WriteBuffer": func(conn net.Conn) error {
			return conn.(N.ExtendedWriter).WriteBuffer(buf.As([]byte("|LATE")).ToOwned())
		},
		"WriteVectorised": func(conn net.Conn) error {
			writer, created := conn.(interface {
				CreateVectorisedWriter() (N.VectorisedWriter, bool)
			}).CreateVectorisedWriter()
			require.True(t, created)
			return writer.WriteVectorised([]*buf.Buffer{buf.As([]byte("|LATE")).ToOwned()})
		},
	}
	for name, lateWrite := range lateWrites {
		t.Run(name, func(t *testing.T) {
			serviceAddress := startLocalSnellService(t, service)
			var proxy countingTCPProxy
			proxy.Start(t, serviceAddress)
			client := newClient(M.ParseSocksaddr(proxy.address))
			defer client.Close()
			destination := M.ParseSocksaddrHostPort("127.0.0.1", 443)

			first, err := client.DialContext(context.Background(), destination)
			require.NoError(t, err)
			_, err = first.Write([]byte("first"))
			require.NoError(t, err)
			require.NoError(t, N.CloseWrite(first))
			require.NoError(t, first.SetReadDeadline(time.Now().Add(5*time.Second)))
			echo, err := io.ReadAll(first)
			require.NoError(t, err)
			require.Equal(t, "first", string(echo))
			require.NoError(t, first.Close())

			second, err := client.DialContext(context.Background(), destination)
			require.NoError(t, err)
			defer second.Close()
			_, err = second.Write([]byte("second"))
			require.NoError(t, err)

			require.ErrorIs(t, lateWrite(first), net.ErrClosed)

			require.NoError(t, N.CloseWrite(second))
			require.NoError(t, second.SetReadDeadline(time.Now().Add(5*time.Second)))
			echo, err = io.ReadAll(second)
			require.NoError(t, err)
			require.Equal(t, "second", string(echo))
			require.EqualValues(t, 1, proxy.count.Load(), "session was not reused")
		})
	}
}

func TestV4ReuseWriteAfterClose(t *testing.T) {
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: localEchoHandler{}})
	require.NoError(t, err)
	testReuseWriteAfterClose(t, service, func(server M.Socksaddr) reuseDialer {
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

func TestV6ReuseWriteAfterClose(t *testing.T) {
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Handler: localEchoHandler{}})
	require.NoError(t, err)
	testReuseWriteAfterClose(t, service, func(server M.Socksaddr) reuseDialer {
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}
