//go:build !unix || aix

package reuse

import "net"

// CheckConn does not probe idle connections on this platform.
func CheckConn(net.Conn) error {
	return nil
}
