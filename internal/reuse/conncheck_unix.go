//go:build unix && !aix

package reuse

import (
	"errors"
	"io"
	"net"
	"syscall"

	"github.com/sagernet/sing/common"
)

var errUnexpectedRead = errors.New("snell: unexpected data on idle reuse connection")

// CheckConn reports whether an idle pooled connection can still be reused.
//
// Pooled sessions are not read while idle, so a peer FIN, RST or a kernel
// timeout goes unnoticed, and reusing such a session fails the next request
// immediately with "write request: broken pipe" or "read reply: EOF".
// The socket is probed with recvfrom(MSG_PEEK|MSG_DONTWAIT), which neither
// blocks nor consumes data: EOF, a socket error or unexpected data mark it
// unusable, EAGAIN means it is healthy. Control is used instead of Read so the
// probe does not wait for the read lock held by a concurrent reader.
// Connections without an accessible file descriptor are not checked.
func CheckConn(conn net.Conn) error {
	syscallConn, loaded := common.Cast[syscall.Conn](conn)
	if !loaded {
		return nil
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return err
	}
	var checkErr error
	err = rawConn.Control(func(fd uintptr) {
		var buffer [1]byte
		n, _, recvErr := syscall.Recvfrom(int(fd), buffer[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case errors.Is(recvErr, syscall.EAGAIN), errors.Is(recvErr, syscall.EWOULDBLOCK), errors.Is(recvErr, syscall.EINTR):
		case recvErr != nil:
			checkErr = recvErr
		case n == 0:
			checkErr = io.EOF
		default:
			checkErr = errUnexpectedRead
		}
	})
	if err != nil {
		return err
	}
	return checkErr
}
