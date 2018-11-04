package socks5

import (
	"bufio"
	"errors"
	"io"
	"net"
)

type Request struct {
	Command     CommandType
	AddressType AddressType
	Address     net.IP
	Fqdn        string
	Port        uint16

	stream io.Writer
	bufIo  *bufio.Reader
}

type Response struct {
	Type        ReplyType
	AddressType AddressType
	BindAddress net.IP
	BindPort    uint16
	BindFqdn    string
}

func checkMethodAvailable(buf []byte) bool {
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			return true
		}
	}
	return false
}

func (req *Request) recvMethodSelection() ([]byte, error) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(req.bufIo, buf); err != nil {
		return nil, err
	}

	if buf[0] != SocksVersion {
		return nil, errors.New("socks version is not 5")
	}

	if buf[1] == 0 {
		return nil, errors.New("socks auth method is not specified")
	}

	methodsLen := int(buf[1])
	buf = make([]byte, methodsLen)
	if _, err := io.ReadFull(req.bufIo, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func (req *Request) sendMethodSelection(method byte) error {
	msg := []byte{SocksVersion, method}
	_, err := req.stream.Write(msg)
	return err
}

func (req *Request) recvRequest() error {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(req.bufIo, buf); err != nil {
		return err
	}

	if buf[0] != SocksVersion {
		return errors.New("socks version is not 5")
	}

	if buf[1] < 1 || buf[1] > 3 {
		return errors.New("invalid command")
	}
	req.Command = CommandType(buf[1])
	req.AddressType = AddressType(buf[3])

	switch req.AddressType {
	case AddrIPv4:
		buf = make([]byte, 4+2)
		if _, err := io.ReadFull(req.bufIo, buf); err != nil {
			return err
		}

		req.Address = net.IPv4(buf[0], buf[1], buf[2], buf[3])
		req.Port = uint16(buf[4])<<8 | uint16(buf[5])
	case AddrDns:
		len, err := req.bufIo.ReadByte()
		if err != nil {
			return err
		}

		buf = make([]byte, len+2)
		if _, err := io.ReadFull(req.bufIo, buf); err != nil {
			return err
		}
		req.Fqdn = string(buf[:len])
		req.Port = uint16(buf[len])<<8 | uint16(buf[len+1])
	default:
		return errors.New("invalid or unsupported address type")
	}

	return nil
}

func NewRequest(stream io.ReadWriter) *Request {
	return &Request{
		stream: stream,
		bufIo:  bufio.NewReader(stream),
	}
}

func (req *Request) Negotiate() error {
	methods, err := req.recvMethodSelection()
	if err != nil {
		return err
	}

	if !checkMethodAvailable(methods) {
		if err := req.sendMethodSelection(0xff); err != nil {
			return err
		}
		return errors.New("socks auth method is not supported")
	}

	if err := req.sendMethodSelection(0); err != nil {
		return err
	}

	if err := req.recvRequest(); err != nil {
		return err
	}
	return nil
}

func (req *Request) SendResponse(res Response) error {
	buf := []byte{
		5,
		byte(res.Type),
		0,
		byte(res.AddressType),
	}

	switch res.AddressType {
	case AddrIPv4:
		buf = append(buf, []byte(res.BindAddress.To4())...)
	case AddrDns:
		buf = append(buf, append([]byte{byte(len(res.BindFqdn))}, res.BindFqdn...)...)
	case AddrIPv6:
		buf = append(buf, []byte(res.BindAddress.To16())...)
	default:
		return errors.New("invalid or unsupported address type")
	}
	buf = append(buf, byte(res.BindPort>>8), byte(res.BindPort&0xff))

	if _, err := req.stream.Write(buf); err != nil {
		return err
	}

	return nil
}
