// Package eof reports a transport EOF as an unexpected end of stream.
package eof

import "io"

// UnexpectedReader returns io.ErrUnexpectedEOF instead of io.EOF from the
// transport. A client stream ends with a zero chunk record, so a server that
// closes the transport without one has cut the stream short.
type UnexpectedReader struct {
	io.Reader
}

func (r UnexpectedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

func (r UnexpectedReader) Upstream() any {
	return r.Reader
}

// Unexpected returns io.ErrUnexpectedEOF for io.EOF. Use it for reads inside
// a record, where the stream cannot end on either side.
func Unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
