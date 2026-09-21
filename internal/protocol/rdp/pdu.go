// Package rdp implements the connection-establishment subset of Microsoft's
// Remote Desktop Protocol wire format (MS-RDPBCGR): TPKT framing, the X.224
// Connection Request/Confirm exchange, and the RDP Negotiation
// Request/Response/Failure extension used to agree on a security protocol
// (plain RDP security, TLS, or CredSSP/NLA) before any credential is
// exchanged.
//
// This package deliberately stops at negotiation. It does not implement
// CredSSP's NTLM/Kerberos credential exchange, nor the graphics/virtual
// channel layers of a full RDP client — those are out of scope for a
// connection-handling foundation library. When a server requires CredSSP
// (NLA), callers get a clearly typed "unsupported auth method" signal
// rather than a simulated or best-effort credential exchange.
package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// SecurityProtocol is a bitmask of the RDP security protocols a client can
// offer, and a server can select, during negotiation (MS-RDPBCGR 2.2.1.1.1).
type SecurityProtocol uint32

const (
	// ProtoRDP is the original, weak "Standard RDP Security" (RC4-based).
	ProtoRDP SecurityProtocol = 0x00000000
	// ProtoSSL indicates the connection should be upgraded to TLS.
	ProtoSSL SecurityProtocol = 0x00000001
	// ProtoHybrid indicates CredSSP (NLA): TLS followed by a CredSSP
	// credential exchange. This library negotiates but does not perform
	// the CredSSP exchange itself; see the package doc comment.
	ProtoHybrid SecurityProtocol = 0x00000002
	// ProtoRDSTLS indicates the RDSTLS protocol (rarely offered).
	ProtoRDSTLS SecurityProtocol = 0x00000004
	// ProtoHybridEx is CredSSP with the "early user auth result" extension.
	ProtoHybridEx SecurityProtocol = 0x00000008
)

func (p SecurityProtocol) String() string {
	switch {
	case p&ProtoHybridEx != 0:
		return "CredSSP (NLA, early-auth-result)"
	case p&ProtoHybrid != 0:
		return "CredSSP (NLA)"
	case p&ProtoRDSTLS != 0:
		return "RDSTLS"
	case p&ProtoSSL != 0:
		return "TLS"
	default:
		return "Standard RDP Security"
	}
}

// FailureCode enumerates the values a server can send in an RDP
// Negotiation Failure PDU (MS-RDPBCGR 2.2.1.2.2).
type FailureCode uint32

const (
	FailureSSLRequiredByServer             FailureCode = 1
	FailureSSLNotAllowedByServer           FailureCode = 2
	FailureSSLCertNotOnServer              FailureCode = 3
	FailureInconsistentFlags               FailureCode = 4
	FailureHybridRequiredByServer          FailureCode = 5
	FailureSSLWithUserAuthRequiredByServer FailureCode = 6
)

// String returns a human-readable description of the failure code.
func (c FailureCode) String() string {
	switch c {
	case FailureSSLRequiredByServer:
		return "server requires TLS"
	case FailureSSLNotAllowedByServer:
		return "server does not allow TLS"
	case FailureSSLCertNotOnServer:
		return "server has no certificate configured for TLS"
	case FailureInconsistentFlags:
		return "inconsistent negotiation flags"
	case FailureHybridRequiredByServer:
		return "server requires CredSSP/NLA"
	case FailureSSLWithUserAuthRequiredByServer:
		return "server requires TLS with inline user authentication"
	default:
		return fmt.Sprintf("unknown failure code %d", uint32(c))
	}
}

// Well-known X.224 TPDU codes used in the byte this package inspects.
const (
	tpduCodeCR = 0xE0 // Connection Request
	tpduCodeCC = 0xD0 // Connection Confirm
)

// Negotiation extension PDU types (MS-RDPBCGR 2.2.1.1.1 / 2.2.1.2.1).
const (
	typeNegotiationRequest  = 0x01
	typeNegotiationResponse = 0x02
	typeNegotiationFailure  = 0x03
)

const maxTPKTLength = 65535

// WriteConnectionRequest writes a complete TPKT-framed X.224 Connection
// Request TPDU carrying an RDP Negotiation Request that offers
// requestedProtocols. cookie, if non-empty, is sent as the routing token /
// "Cookie: mstshash=..." line ahead of the negotiation block, as some load
// balancers require.
func WriteConnectionRequest(w io.Writer, cookie string, requestedProtocols SecurityProtocol) error {
	var x224 []byte
	x224 = append(x224, tpduCodeCR, 0x00, 0x00, 0x00, 0x00, 0x00) // CR, DST-REF, SRC-REF, class option
	if cookie != "" {
		x224 = append(x224, []byte(cookie)...)
		x224 = append(x224, 0x0D, 0x0A) // CRLF terminator per MS-RDPBCGR 2.2.1.1
	}
	x224 = append(x224, encodeNegotiationRequest(requestedProtocols)...)

	frame, err := frameTPKT(withX224LengthIndicator(x224))
	if err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

func encodeNegotiationRequest(protocols SecurityProtocol) []byte {
	buf := make([]byte, 8)
	buf[0] = typeNegotiationRequest
	buf[1] = 0x00 // flags
	binary.LittleEndian.PutUint16(buf[2:4], 8)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(protocols))
	return buf
}

// withX224LengthIndicator prepends the single-byte X.224 length indicator
// (the length of everything that follows it in the TPDU).
func withX224LengthIndicator(body []byte) []byte {
	out := make([]byte, 0, len(body)+1)
	out = append(out, byte(len(body)))
	out = append(out, body...)
	return out
}

// frameTPKT wraps x224TPDU in a TPKT header: version(1)=3, reserved(1)=0,
// length(2, big-endian, total including this 4-byte header).
func frameTPKT(x224TPDU []byte) ([]byte, error) {
	total := len(x224TPDU) + 4
	if total > maxTPKTLength {
		return nil, fmt.Errorf("rdp: TPDU too large for TPKT framing (%d bytes)", total)
	}
	out := make([]byte, 4, total)
	out[0] = 3
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	return append(out, x224TPDU...), nil
}

// ConnectionConfirm is the parsed result of reading a server's response to
// a Connection Request.
type ConnectionConfirm struct {
	// Selected is the security protocol the server chose. Zero value
	// (ProtoRDP) is valid and means "Standard RDP Security", but is also
	// what a pre-negotiation-extension server implicitly means by
	// sending a bare X.224 CC with no negotiation block at all — check
	// NegotiationPresent to distinguish the two.
	Selected SecurityProtocol
	// NegotiationPresent reports whether the server's CC included an RDP
	// Negotiation Response/Failure block at all. Very old servers (or
	// non-RDP services that happen to produce a plausible-looking X.224
	// CC) omit it entirely.
	NegotiationPresent bool
	// Failed reports whether the server sent a Negotiation Failure PDU
	// instead of a Response. When true, FailureCode is meaningful and
	// Selected is the zero value.
	Failed bool
	// FailureCode is populated when Failed is true.
	FailureCode FailureCode
}

// ReadTPKT reads exactly one TPKT-framed PDU from r and returns its payload
// (everything after the 4-byte TPKT header). It enforces the protocol's
// length field against a sane maximum so a malicious or corrupted peer
// cannot force an unbounded allocation.
func ReadTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 3 {
		return nil, &MalformedError{Reason: fmt.Sprintf("unexpected TPKT version byte 0x%02x", hdr[0]), NotRDP: true}
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < 4 || total > maxTPKTLength {
		return nil, &MalformedError{Reason: fmt.Sprintf("implausible TPKT length %d", total)}
	}
	payload := make([]byte, total-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// MalformedError indicates the peer's bytes could not be parsed as a valid
// TPKT/X.224/negotiation PDU at all — i.e. it is very unlikely to be an RDP
// server, as opposed to a real RDP server reporting a negotiation failure.
type MalformedError struct {
	Reason string
	// NotRDP is true when the very first bytes were not TPKT at all, i.e.
	// the peer is almost certainly speaking a different protocol.
	NotRDP bool
}

func (e *MalformedError) Error() string { return "rdp: malformed PDU: " + e.Reason }

// ParseConnectionConfirm parses the X.224 payload (as returned by
// ReadTPKT) of a server's response to a Connection Request.
func ParseConnectionConfirm(x224 []byte) (*ConnectionConfirm, error) {
	if len(x224) < 1 {
		return nil, &MalformedError{Reason: "empty X.224 payload"}
	}
	liLen := int(x224[0])
	if liLen < 6 || len(x224) < 1+liLen {
		return nil, &MalformedError{Reason: "truncated X.224 header"}
	}
	body := x224[1 : 1+liLen]
	if body[0] != tpduCodeCC {
		return nil, &MalformedError{Reason: fmt.Sprintf("expected X.224 CC (0x%02x), got 0x%02x", tpduCodeCC, body[0])}
	}

	cc := &ConnectionConfirm{}
	// body layout: CC(1) DST-REF(2) SRC-REF(2) class-option(1) [negotiation block]
	const fixedLen = 6
	if len(body) <= fixedLen {
		return cc, nil // no negotiation block: pre-extension server
	}
	neg := body[fixedLen:]
	if len(neg) < 8 {
		return nil, &MalformedError{Reason: "truncated negotiation block"}
	}
	cc.NegotiationPresent = true
	negType := neg[0]
	negLen := binary.LittleEndian.Uint16(neg[2:4])
	if negLen != 8 {
		return nil, &MalformedError{Reason: fmt.Sprintf("unexpected negotiation block length %d", negLen)}
	}
	value := binary.LittleEndian.Uint32(neg[4:8])
	switch negType {
	case typeNegotiationResponse:
		cc.Selected = SecurityProtocol(value)
	case typeNegotiationFailure:
		cc.Failed = true
		cc.FailureCode = FailureCode(value)
	default:
		return nil, &MalformedError{Reason: fmt.Sprintf("unexpected negotiation PDU type 0x%02x", negType)}
	}
	return cc, nil
}
