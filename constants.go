package socks5

type CommandType byte

const (
	CommandConnect      CommandType = 1
	CommandBind         CommandType = 2
	CommandUdpAssociate CommandType = 3
)

func (command CommandType) String() string {
	switch command {
	case CommandConnect:
		return "CommandConnect"
	case CommandBind:
		return "CommandBind"
	case CommandUdpAssociate:
		return "CommandUdpAssociate"
	default:
		return "Unknown"
	}
}

type AddressType byte

const (
	AddrIPv4 AddressType = 1
	AddrDns  AddressType = 3
	AddrIPv6 AddressType = 4
)

func (addrType AddressType) String() string {
	switch addrType {
	case AddrIPv4:
		return "AddrIPv4"
	case AddrDns:
		return "AddrDns"
	case AddrIPv6:
		return "AddrIPv6"
	default:
		return "Unknown"
	}
}

type ReplyType byte

const (
	ReplySuccess            ReplyType = 0
	ReplyFailed             ReplyType = 1
	ReplyUnreached          ReplyType = 3
	ReplyNoSuchHost         ReplyType = 4
	ReplyConnectDenied      ReplyType = 5
	ReplyTtlOver            ReplyType = 6
	ReplyUnsupportedCommand ReplyType = 7
	ReplyUnsupportedAddress ReplyType = 8
)

func (replyType ReplyType) String() string {
	switch replyType {
	case ReplySuccess:
		return "ReplySuccess"
	case ReplyFailed:
		return "ReplyFailed"
	case ReplyUnreached:
		return "ReplyUnreached"
	case ReplyNoSuchHost:
		return "ReplyNoSuchHost"
	case ReplyConnectDenied:
		return "ReplyConnectDenied"
	case ReplyTtlOver:
		return "ReplyTtlOver"
	case ReplyUnsupportedCommand:
		return "ReplyUnsupportedCommand"
	case ReplyUnsupportedAddress:
		return "ReplyUnsupportedAddress"
	default:
		return "Unknown"
	}
}

const SocksVersion = 5
