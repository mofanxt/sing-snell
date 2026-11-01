package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type reuseTCPClient interface {
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

type countingTCPProxy struct {
	address string
	count   atomic.Int32
	access  sync.Mutex
	clients []*net.TCPConn
	uplink  []*atomic.Int64
}

// Uplink returns the client-to-server bytes forwarded on the index-th accepted connection.
func (p *countingTCPProxy) Uplink(index int) int64 {
	p.access.Lock()
	defer p.access.Unlock()
	return p.uplink[index].Load()
}

type countingWriter struct {
	io.Writer
	counter *atomic.Int64
}

func (w countingWriter) Write(b []byte) (int, error) {
	// Count before forwarding so the server never sees bytes that are not counted yet.
	w.counter.Add(int64(len(b)))
	return w.Writer.Write(b)
}

func (p *countingTCPProxy) Start(t *testing.T, target string) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p.address = listener.Addr().String()
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			p.count.Add(1)
			counter := new(atomic.Int64)
			p.access.Lock()
			if tcpConn, isTCP := conn.(*net.TCPConn); isTCP {
				p.clients = append(p.clients, tcpConn)
			}
			p.uplink = append(p.uplink, counter)
			p.access.Unlock()
			go p.Proxy(conn, target, counter)
		}
	}()
}

// DropClients closes every accepted client connection, with an RST when reset
// is set, to simulate a pooled session dropped by the peer while idle.
func (p *countingTCPProxy) DropClients(reset bool) {
	p.access.Lock()
	clients := p.clients
	p.clients = nil
	p.access.Unlock()
	for _, conn := range clients {
		if reset {
			conn.SetLinger(0)
		}
		conn.Close()
	}
}

func (p *countingTCPProxy) Proxy(conn net.Conn, target string, uplink *atomic.Int64) {
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		conn.Close()
		return
	}
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		io.Copy(countingWriter{Writer: upstream, counter: uplink}, conn)
		N.CloseWrite(upstream)
	}()
	go func() {
		defer wait.Done()
		io.Copy(conn, upstream)
		N.CloseWrite(conn)
	}()
	wait.Wait()
	conn.Close()
	upstream.Close()
}

type reuseScenario struct {
	client      reuseTCPClient
	destination M.Socksaddr
}

func startTCPHalfCloseEcho(t *testing.T, closeWriteDelay ...time.Duration) uint16 {
	delay := time.Duration(0)
	if len(closeWriteDelay) > 0 {
		delay = closeWriteDelay[0]
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				payload, readErr := io.ReadAll(conn)
				if readErr != nil {
					return
				}
				_, writeErr := io.Copy(conn, bytes.NewReader(payload))
				if writeErr != nil {
					return
				}
				time.Sleep(delay)
				N.CloseWrite(conn)
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func startTCPHalfCloseTailEcho(t *testing.T, tailLen int, closeWriteDelay time.Duration) uint16 {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer conn.Close()
				payload, readErr := io.ReadAll(conn)
				if readErr != nil {
					return
				}
				_, writeErr := io.Copy(conn, bytes.NewReader(payload))
				if writeErr != nil {
					return
				}
				if tailLen > 0 {
					tail := bytes.Repeat([]byte{0x5A}, tailLen)
					_, writeErr = conn.Write(tail)
					if writeErr != nil {
						return
					}
				}
				time.Sleep(closeWriteDelay)
				N.CloseWrite(conn)
				time.Sleep(200 * time.Millisecond)
			}()
		}
	}()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func (s reuseScenario) RoundTrip(t *testing.T, label string) {
	payload := make([]byte, 4*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	copy(payload, []byte(label))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Equal(t, len(payload), len(received), "%s response length", label)
	require.True(t, bytes.Equal(payload, received), "%s payload mismatch", label)
	require.NoError(t, conn.Close())
}

func (s reuseScenario) PartialEchoRoundTrip(t *testing.T, label string, payloadLen int, echoLen int) {
	payload := make([]byte, payloadLen)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	copy(payload, []byte(label))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload[:echoLen], received), "%s payload mismatch", label)
	require.NoError(t, conn.Close())
}

func (s reuseScenario) CloseBeforeServerEOF(t *testing.T, label string, waitAfterClose time.Duration) {
	payload := make([]byte, 4*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	copy(payload, []byte(label))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "%s payload mismatch", label)
	closeStart := time.Now()
	require.NoError(t, conn.Close())
	if time.Since(closeStart) > 250*time.Millisecond {
		t.Fatalf("%s close waited for server EOF instead of leaving the session draining", label)
	}
	time.Sleep(waitAfterClose)
}

func (s reuseScenario) CloseWhileReadBlocked(t *testing.T, label string) {
	payload := make([]byte, 4*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	copy(payload, []byte(label))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received := make([]byte, len(payload))
	_, err = io.ReadFull(conn, received)
	require.NoError(t, err)
	require.True(t, bytes.Equal(payload, received), "%s payload mismatch", label)

	readStarted := make(chan struct{})
	readResult := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		close(readStarted)
		var one [1]byte
		n, readErr := conn.Read(one[:])
		readResult <- struct {
			n   int
			err error
		}{n: n, err: readErr}
	}()
	<-readStarted
	select {
	case result := <-readResult:
		t.Fatalf("%s read returned before close: n=%d err=%v", label, result.n, result.err)
	case <-time.After(50 * time.Millisecond):
	}

	closeStart := time.Now()
	require.NoError(t, conn.Close())
	if time.Since(closeStart) > 250*time.Millisecond {
		t.Fatalf("%s close waited for server EOF instead of leaving the active read to finish", label)
	}
	select {
	case result := <-readResult:
		t.Fatalf("%s read returned before server EOF after close: n=%d err=%v", label, result.n, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case result := <-readResult:
		require.Zero(t, result.n, "%s read bytes", label)
		require.ErrorIs(t, result.err, io.EOF, "%s read error", label)
	case <-time.After(3 * time.Second):
		t.Fatalf("%s active read did not finish after server EOF", label)
	}
}

func (s reuseScenario) ReadWaiter(t *testing.T, label string) {
	payload := make([]byte, 4*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)
	copy(payload, []byte(label))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	readWaiter, created := bufio.CreateReadWaiter(conn)
	require.True(t, created)
	needCopy := readWaiter.InitializeReadWaiter(N.ReadWaitOptions{FrontHeadroom: 2048, RearHeadroom: 256, MTU: 1200})
	require.False(t, needCopy)
	_, err = conn.Write(payload)
	require.NoError(t, err)
	require.NoError(t, N.CloseWrite(conn))
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	received := make([]byte, 0, len(payload))
	for len(received) < len(payload) {
		buffer, readErr := readWaiter.WaitReadBuffer()
		require.NoError(t, readErr)
		require.GreaterOrEqual(t, buffer.Start(), 2048)
		require.GreaterOrEqual(t, buffer.FreeLen(), 256)
		received = append(received, buffer.Bytes()...)
		buffer.Release()
	}
	require.Equal(t, len(payload), len(received), "%s response length", label)
	require.True(t, bytes.Equal(payload, received), "%s payload mismatch", label)
	require.NoError(t, conn.Close())
}

// PrefersMostRecent opens two concurrent sessions so the client dials two
// connections, releases them oldest first, and checks that the next request
// reuses the most recently released one.
func (s reuseScenario) PrefersMostRecent(t *testing.T, proxy *countingTCPProxy, label string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	older, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	newer, err := s.client.DialContext(ctx, s.destination)
	require.NoError(t, err)
	for _, conn := range []net.Conn{older, newer} {
		_, err = conn.Write([]byte(label))
		require.NoError(t, err)
		require.NoError(t, N.CloseWrite(conn))
		require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
		_, err = io.ReadAll(conn)
		require.NoError(t, err)
	}
	require.NoError(t, older.Close())
	require.NoError(t, newer.Close())
	require.Equal(t, int32(2), proxy.count.Load())
	time.Sleep(100 * time.Millisecond)
	olderBytes, newerBytes := proxy.Uplink(0), proxy.Uplink(1)
	s.RoundTrip(t, label+"-reused")
	require.Equal(t, int32(2), proxy.count.Load())
	require.Equal(t, olderBytes, proxy.Uplink(0), "%s reused the oldest pooled session", label)
	require.Greater(t, proxy.Uplink(1), newerBytes, "%s did not reuse the most recent pooled session", label)
}
