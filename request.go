package snell

import (
	"io"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type Request struct {
	Command        byte
	ClientID       []byte
	Destination    M.Socksaddr
	TCPFingerprint *TCPFingerprint
}

func (r Request) Write(buffer *buf.Buffer) error {
	if len(r.ClientID) > 255 {
		return E.New("snell: client id too long")
	}
	_, err := buffer.Write([]byte{RequestVersion, r.Command, byte(len(r.ClientID))})
	if err != nil {
		return err
	}
	if len(r.ClientID) > 0 {
		_, err = buffer.Write(r.ClientID)
		if err != nil {
			return err
		}
	}
	switch r.Command {
	case CommandConnectFingerprint:
		if err := WriteConnectAddress(buffer, r.Destination); err != nil {
			return err
		}
		return WriteTCPFingerprint(buffer, r.TCPFingerprint)
	case CommandConnect, CommandConnectV2:
		return WriteConnectAddress(buffer, r.Destination)
	case CommandPing, CommandUDP:
		return nil
	default:
		return E.Extend(ErrUnsupportedCommand, r.Command)
	}
}

func (r Request) Len() int {
	requestLen := 3 + len(r.ClientID)
	switch r.Command {
	case CommandConnectFingerprint:
		optionLen := 0
		if r.TCPFingerprint != nil {
			optionLen = len(r.TCPFingerprint.Options)
		}
		return requestLen + 1 + len(r.Destination.AddrString()) + 2 + 2 + 6 + optionLen
	case CommandConnect, CommandConnectV2:
		return requestLen + 1 + len(r.Destination.AddrString()) + 2
	default:
		return requestLen
	}
}

func ReadRequest(reader io.Reader) (Request, error) {
	return readRequest(reader, false, false)
}

// ReadV6Request 按 v6 规则读取请求，仅在调用方显式允许时解析私有扩展。
func ReadV6Request(reader io.Reader, allowFingerprint bool) (Request, error) {
	return readRequest(reader, allowFingerprint, true)
}

func readRequest(reader io.Reader, allowFingerprint, v6 bool) (Request, error) {
	prefix := make([]byte, 3)
	_, err := io.ReadFull(reader, prefix)
	if err != nil {
		return Request{}, err
	}
	if prefix[0] != RequestVersion {
		return Request{}, E.Extend(ErrBadVersion, "request version ", prefix[0])
	}
	clientIDLen := int(prefix[2])
	request := Request{Command: prefix[1]}
	// v6 的 PING 忽略前缀中的客户端 ID 长度。
	if v6 && request.Command == CommandPing {
		return request, nil
	}
	if clientIDLen > 0 {
		request.ClientID = make([]byte, clientIDLen)
		_, err = io.ReadFull(reader, request.ClientID)
		if err != nil {
			return Request{}, err
		}
	}
	switch request.Command {
	case CommandConnectFingerprint:
		if !allowFingerprint {
			if v6 {
				return Request{}, E.New("snell: TCP fingerprint extension disabled")
			}
			return Request{}, E.Extend(ErrUnsupportedCommand, request.Command)
		}
		fallthrough
	case CommandConnect, CommandConnectV2:
		request.Destination, err = ReadConnectAddress(reader)
		if err != nil {
			return Request{}, err
		}
		if request.Command == CommandConnectFingerprint {
			request.TCPFingerprint, err = ReadTCPFingerprint(reader)
			if err != nil {
				return Request{}, err
			}
		}
	case CommandPing, CommandUDP:
	default:
		return Request{}, E.Extend(ErrUnsupportedCommand, request.Command)
	}
	return request, nil
}

func ReadServerError(record *buf.Buffer) error {
	errorCode, err := record.ReadByte()
	if err != nil {
		return err
	}
	message, err := M.ReadSockString(record)
	if err != nil {
		return err
	}
	// Surge 6.7.0 (11520): SNConnectorV4::socket:didReadData: rejects server-error replies unless the frame is
	// exactly code, message length, and message bytes.
	if !record.IsEmpty() {
		return E.New("snell: server error reply has trailing data")
	}
	return E.New("snell: server error ", errorCode, ": ", message)
}
