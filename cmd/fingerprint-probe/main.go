// 此命令只供隔离实验，用自定义特征验证多跳透传和末跳SYN。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	snell "github.com/mofanxt/sing-snell"
	"github.com/mofanxt/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func main() {
	var cfg struct{ Server, PSK, UserKey, Target string }
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &cfg); err != nil {
		panic(err)
	}
	c, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(cfg.PSK), UserKey: []byte(cfg.UserKey), Server: M.ParseSocksaddr(cfg.Server), Dialer: N.SystemDialer, Reuse: true, Fingerprint: true})
	if err != nil {
		panic(err)
	}
	defer c.Close()
	apple := &snell.TCPFingerprint{TTL: 64, Window: 65535, ZeroIPID: true, Options: []byte{2, 4, 5, 180, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 4, 2, 0, 0}}
	noTS := &snell.TCPFingerprint{TTL: 128, Window: 64240, Options: []byte{2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2}}
	for i, f := range []*snell.TCPFingerprint{apple, noTS, apple, noTS, nil, apple} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, e := c.DialContext(snell.ContextWithTCPFingerprint(ctx, f), M.ParseSocksaddr(cfg.Target))
		if e != nil {
			panic(e)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		_, e = fmt.Fprintf(conn, "GET /probe/%d HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n", i)
		if e != nil {
			panic(e)
		}
		resp, e := http.ReadResponse(bufio.NewReader(conn), nil)
		if e != nil {
			panic(e)
		}
		body, e := io.ReadAll(resp.Body)
		if e != nil {
			panic(e)
		}
		resp.Body.Close()
		var observed map[string]any
		if e = json.Unmarshal(body, &observed); e != nil {
			panic(e)
		}
		kind := "original"
		if f == apple {
			kind = "apple"
		} else if f == noTS {
			kind = "no_timestamp"
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"profile": kind, "observed": observed})
		N.CloseWrite(conn)
		io.Copy(io.Discard, conn)
		conn.Close()
		cancel()
		time.Sleep(30 * time.Millisecond)
	}
}
