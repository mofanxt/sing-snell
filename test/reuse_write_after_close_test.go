package test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
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

// The first write publishes the record writer while other goroutines may ask
// for headroom; run with -race.
func testReuseFirstWriteRace(t *testing.T, service snell.Service, newClient func(server M.Socksaddr) reuseDialer) {
	serviceAddress := startLocalSnellService(t, service)
	client := newClient(M.ParseSocksaddr(serviceAddress))
	defer client.Close()
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 443))
	require.NoError(t, err)
	defer conn.Close()
	type writerState interface {
		FrontHeadroom() int
		NeedHandshakeForWrite() bool
	}
	state := conn.(writerState)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			state.FrontHeadroom()
			state.NeedHandshakeForWrite()
		}
	}()
	_, err = conn.Write([]byte("payload"))
	require.NoError(t, err)
	<-done
	require.False(t, state.NeedHandshakeForWrite())
}

func TestV4ReuseFirstWriteRace(t *testing.T) {
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: localEchoHandler{}})
	require.NoError(t, err)
	testReuseFirstWriteRace(t, service, func(server M.Socksaddr) reuseDialer {
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

func TestV6ReuseFirstWriteRace(t *testing.T) {
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Handler: localEchoHandler{}})
	require.NoError(t, err)
	testReuseFirstWriteRace(t, service, func(server M.Socksaddr) reuseDialer {
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

// stalledReadHandler replies once and then stops reading, so client writes
// eventually block on the socket.
type stalledReadHandler struct {
	localEchoHandler
	release chan struct{}
}

func (h stalledReadHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer func() {
			conn.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		_, err := conn.Write([]byte("reply"))
		if err != nil {
			return
		}
		<-h.release
	}()
}

// Close must not wait for a write that is blocked because the peer stopped
// reading; it closes the session, which also ends the blocked write.
func testReuseCloseDuringBlockedWrite(t *testing.T, newService func(handler stalledReadHandler) snell.Service, newClient func(server M.Socksaddr) reuseDialer) {
	handler := stalledReadHandler{release: make(chan struct{})}
	defer close(handler.release)
	serviceAddress := startLocalSnellService(t, newService(handler))
	client := newClient(M.ParseSocksaddr(serviceAddress))
	defer client.Close()
	conn, err := client.DialContext(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", 443))
	require.NoError(t, err)
	_, err = conn.Write([]byte("request"))
	require.NoError(t, err)
	reply := make([]byte, 5)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, "reply", string(reply))

	var written atomic.Int64
	writeDone := make(chan error, 1)
	go func() {
		chunk := make([]byte, 64*1024)
		for written.Load() < 1<<30 {
			n, err := conn.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	// Wait until the writes stall.
	last := int64(-1)
	for {
		time.Sleep(200 * time.Millisecond)
		current := written.Load()
		if current == last {
			break
		}
		last = current
		select {
		case err := <-writeDone:
			t.Fatalf("writes did not block: %v", err)
		default:
		}
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- conn.Close() }()
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for a blocked write")
	}
	select {
	case err := <-writeDone:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("blocked write did not end after Close")
	}
}

func TestV4ReuseCloseDuringBlockedWrite(t *testing.T) {
	testReuseCloseDuringBlockedWrite(t, func(handler stalledReadHandler) snell.Service {
		service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: handler})
		require.NoError(t, err)
		return service
	}, func(server M.Socksaddr) reuseDialer {
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}

func TestV6ReuseCloseDuringBlockedWrite(t *testing.T) {
	testReuseCloseDuringBlockedWrite(t, func(handler stalledReadHandler) snell.Service {
		service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Handler: handler})
		require.NoError(t, err)
		return service
	}, func(server M.Socksaddr) reuseDialer {
		client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: server})
		require.NoError(t, err)
		return client
	})
}
