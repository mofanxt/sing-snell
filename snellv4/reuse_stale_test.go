package snellv4_test

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// pingHandler 读取一次请求后回写 "pong:" 前缀的响应并结束逻辑连接。
type pingHandler struct{}

func (pingHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer onClose(nil)
		defer conn.Close()
		buffer := make([]byte, 64)
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		_, _ = conn.Write(append([]byte("pong:"), buffer[:n]...))
	}()
}

func (pingHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	onClose(nil)
}

// testServer 是监听回环地址的 Snell v5 服务端，并记录每条已接受的 TCP 连接，便于测试中模拟断线。
type testServer struct {
	listener net.Listener
	access   sync.Mutex
	conns    []*net.TCPConn
	received []*atomic.Int64
}

// countingConn 统计服务端每条连接收到的字节数，用于判断请求走了哪条连接。
type countingConn struct {
	net.Conn
	counter *atomic.Int64
}

func (c countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.counter.Add(int64(n))
	return n, err
}

func newTestServer(t *testing.T, psk []byte, obfs snell.ObfsMode) *testServer {
	t.Helper()
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, ObfsMode: obfs, Handler: pingHandler{}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testServer{listener: listener}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			counter := new(atomic.Int64)
			server.access.Lock()
			server.conns = append(server.conns, conn.(*net.TCPConn))
			server.received = append(server.received, counter)
			server.access.Unlock()
			go service.NewConnection(context.Background(), countingConn{Conn: conn, counter: counter}, M.SocksaddrFromNet(conn.RemoteAddr()), nil)
		}
	}()
	return server
}

func (s *testServer) receivedBytes(index int) int64 {
	s.access.Lock()
	defer s.access.Unlock()
	return s.received[index].Load()
}

// killAll 断开服务端已接受的全部连接；reset 为 true 时发送 RST，否则正常发送 FIN。
func (s *testServer) killAll(reset bool) {
	s.access.Lock()
	defer s.access.Unlock()
	for _, conn := range s.conns {
		if reset {
			_ = conn.SetLinger(0)
		}
		_ = conn.Close()
	}
	s.conns = nil
}

// countingDialer 统计客户端新建到服务端的 TCP 连接数。
type countingDialer struct {
	N.Dialer
	dials atomic.Int32
}

func (d *countingDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.dials.Add(1)
	return d.Dialer.DialContext(ctx, network, destination)
}

func newReuseClient(t *testing.T, server *testServer, psk []byte, obfs snell.ObfsMode) (*snellv4.Client, *countingDialer) {
	t.Helper()
	dialer := &countingDialer{Dialer: N.SystemDialer}
	client, err := snellv4.NewClient(snellv4.ClientOptions{
		PSK:      psk,
		Reuse:    true,
		ObfsMode: obfs,
		ObfsHost: "obfs.example",
		Dialer:   dialer,
		Server:   M.SocksaddrFromNet(server.listener.Addr()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, dialer
}

// roundTrip 通过复用客户端完成一次请求，返回响应内容。
func roundTrip(client *snellv4.Client, payload string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, M.ParseSocksaddrHostPort("example.com", 443))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write([]byte(payload)); err != nil {
		return "", err
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(response), nil
}

// 等待池中会话真正归还（客户端 Close 之后异步完成）。
func waitPooled() { time.Sleep(50 * time.Millisecond) }

func TestReuseHealthyPoolKeepsSingleConnection(t *testing.T) {
	psk := []byte("test-psk")
	server := newTestServer(t, psk, snell.ObfsModeNone)
	client, dialer := newReuseClient(t, server, psk, snell.ObfsModeNone)
	for i := 0; i < 5; i++ {
		response, err := roundTrip(client, "ping")
		if err != nil || response != "pong:ping" {
			t.Fatalf("round trip %d: response=%q err=%v", i, response, err)
		}
		waitPooled()
	}
	if got := dialer.dials.Load(); got != 1 {
		t.Fatalf("healthy pool should reuse one connection, dials=%d", got)
	}
}

// 复现：池中空闲会话的底层 TCP 已被对端断开（RST 或 FIN）后，下一次请求不能直接失败；obfs 包装时同样适用。
func TestReuseSkipsDeadPooledSession(t *testing.T) {
	for _, obfs := range []struct {
		name string
		mode snell.ObfsMode
	}{{"plain", snell.ObfsModeNone}, {"http", snell.ObfsModeHTTP}, {"tls", snell.ObfsModeTLS}} {
		for _, testCase := range []struct {
			name  string
			reset bool
		}{{"rst", true}, {"fin", false}} {
			t.Run(obfs.name+"-"+testCase.name, func(t *testing.T) {
				psk := []byte("test-psk")
				server := newTestServer(t, psk, obfs.mode)
				client, dialer := newReuseClient(t, server, psk, obfs.mode)
				if response, err := roundTrip(client, "first"); err != nil || response != "pong:first" {
					t.Fatalf("first round trip: response=%q err=%v", response, err)
				}
				waitPooled()
				server.killAll(testCase.reset)
				time.Sleep(50 * time.Millisecond)

				start := time.Now()
				response, err := roundTrip(client, "second")
				if err != nil || response != "pong:second" {
					t.Fatalf("request after pooled session died failed after %v: response=%q err=%v", time.Since(start), response, err)
				}
				if got := dialer.dials.Load(); got != 2 {
					t.Fatalf("dead pooled session should be replaced by one new connection, dials=%d", got)
				}
			})
		}
	}
}

// 多个空闲会话时优先复用最近归还的一条（LIFO）：最早归还的连接不应再收到数据。
func TestReusePrefersMostRecentSession(t *testing.T) {
	psk := []byte("test-psk")
	server := newTestServer(t, psk, snell.ObfsModeNone)
	client, dialer := newReuseClient(t, server, psk, snell.ObfsModeNone)

	// 同时打开两条逻辑连接，迫使客户端建立两条 TCP，再按先旧后新的顺序归还。
	ctx := context.Background()
	destination := M.ParseSocksaddrHostPort("example.com", 443)
	older, err := client.DialContext(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := client.DialContext(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, conn := range []net.Conn{older, newer} {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err = conn.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadAll(conn); err != nil {
			t.Fatal(err)
		}
	}
	older.Close()
	newer.Close()
	waitPooled()
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("expected two connections, dials=%d", got)
	}

	olderBytes, newerBytes := server.receivedBytes(0), server.receivedBytes(1)
	if response, err := roundTrip(client, "third"); err != nil || response != "pong:third" {
		t.Fatalf("third round trip: response=%q err=%v", response, err)
	}
	if got := dialer.dials.Load(); got != 2 {
		t.Fatalf("pooled session should be reused without new dial, dials=%d", got)
	}
	if server.receivedBytes(0) != olderBytes {
		t.Fatal("reused the oldest pooled session")
	}
	if server.receivedBytes(1) <= newerBytes {
		t.Fatal("did not reuse the most recently pooled session")
	}
}
