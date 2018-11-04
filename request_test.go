package socks5

import (
	"bytes"
	"net"
	"testing"
)

func TestRequestRecvMethodSelection(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	inout.Write([]byte{
		5, // VER
		2, // NMETHODS
		0, // METHODS
		1,
	})
	methods, err := r.recvMethodSelection()
	if err != nil {
		t.Error("failed to recvMethodSelection", err)
	}
	if !bytes.Equal(methods, []byte{0, 1}) {
		t.Error("returned values did not match")
	}
}

func TestRequestSendMethodSelection(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	if err := r.sendMethodSelection(0); err != nil {
		t.Error("failed to sendMethodSelection", err)
	}
	if !bytes.Equal(inout.Bytes(), []byte{5, 0}) {
		t.Error("returned values did not match")
	}
}

func TestRequestRecvRequestIPv4(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	inout.Write([]byte{
		5,              // Ver
		1,              // Command
		0,              // RSV
		1,              // Addr type
		192, 168, 0, 2, // IP
		0, 80,          // Port
	})

	if err := r.recvRequest(); err != nil {
		t.Error("failed to sendMethodSelection", err)
	}
	if r.Command != CommandConnect {
		t.Error("command did not match", r.Command)
	}
	if r.AddressType != AddrIPv4 {
		t.Error("addressType did not match", r.AddressType)
	}
	if !r.Address.Equal(net.IP{192, 168, 0, 2}) {
		t.Error("address did not match", r.Address)
	}
	if r.Port != 80 {
		t.Error("port did not match", r.Port)
	}
}

func TestRequestRecvRequestFQDN(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	inout.Write([]byte{
		5,                                                  // Ver
		1,                                                  // Command
		0,                                                  // RSV
		3,                                                  // Addr type
		11,                                                 // Length of Fqdn
		101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, // Fqdn: example.com
		0, 80,                                              // Port
	})

	if err := r.recvRequest(); err != nil {
		t.Error("failed to sendMethodSelection", err)
	}
	if r.Command != CommandConnect {
		t.Error("command did not match", r.Command)
	}
	if r.AddressType != AddrDns {
		t.Error("addressType did not match", r.AddressType)
	}
	if r.Fqdn != "example.com" {
		t.Error("fqdn did not match", r.Fqdn)
	}
	if r.Port != 80 {
		t.Error("port did not match", r.Port)
	}
}

func TestRequestSendResponseIPv4(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	res := Response{
		Type:        ReplySuccess,
		AddressType: AddrIPv4,
		BindAddress: net.IPv4(192, 168, 0, 5),
		BindPort:    9090,
	}
	if err := r.SendResponse(res); err != nil {
		t.Error("failed to SendResponse", err)
	}
	expected := []byte{
		5,              // Ver
		0,              // Reply type
		0,              // RSV
		1,              // Addr type
		192, 168, 0, 5, // IP
		35, 130,        // Port
	}
	if !bytes.Equal(inout.Bytes(), expected) {
		t.Error("returned values did not match", inout.Bytes())
	}
}

func TestRequestSendResponseDNS(t *testing.T) {
	inout := new(bytes.Buffer)

	r := NewRequest(inout)
	res := Response{
		Type:        ReplySuccess,
		AddressType: AddrDns,
		BindFqdn:    "example.com",
		BindPort:    9090,
	}
	if err := r.SendResponse(res); err != nil {
		t.Error("failed to SendResponse", err)
	}
	expected := []byte{
		5,                                                  // Ver
		0,                                                  // Reply type
		0,                                                  // RSV
		3,                                                  // Addr type
		11,                                                 // Length of Fqdn
		101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, // Fqdn: example.com
		35, 130,                                            // Port
	}
	if !bytes.Equal(inout.Bytes(), expected) {
		t.Error("returned values did not match", inout.Bytes())
	}
}
