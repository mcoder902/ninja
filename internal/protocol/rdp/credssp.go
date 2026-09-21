package rdp

import (
	"context"
	"encoding/asn1"
	"fmt"
	"io"
	"net"
)

const (
	StatusLogonFailure    uint32 = 0xC000006D
	StatusWrongPassword   uint32 = 0xC000006A
	StatusAccountLocked   uint32 = 0xC0000234
	StatusAccountDisabled uint32 = 0xC0000072
	StatusPasswordExpired uint32 = 0xC0000071
)

type TSRequest struct {
	Version    int        `asn1:"explicit,tag:0"`
	NegoTokens []NegoData `asn1:"explicit,optional,tag:1"`
	AuthInfo   []byte     `asn1:"explicit,optional,tag:2"`
	PubKeyAuth []byte     `asn1:"explicit,optional,tag:3"`
	ErrorCode  int        `asn1:"explicit,optional,tag:4"`
}

type NegoData struct {
	NegoToken []byte `asn1:"explicit,tag:0"`
}

type AuthError struct {
	NTStatus uint32
	Message  string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("credssp: %s (NTSTATUS: 0x%08X)", e.Message, e.NTStatus)
}

func AuthenticateCredSSP(ctx context.Context, conn net.Conn, domain, user, password string) error {
	type1 := GenerateNTLMNegotiate()
	req1 := TSRequest{
		Version: 2,
		NegoTokens: []NegoData{
			{NegoToken: type1},
		},
	}
	if err := writeTSRequest(conn, req1); err != nil {
		return err
	}

	resp1, err := readTSRequest(conn)
	if err != nil {
		return err
	}
	if resp1.ErrorCode != 0 {
		return mapNTStatus(uint32(resp1.ErrorCode))
	}
	if len(resp1.NegoTokens) == 0 {
		return fmt.Errorf("credssp: empty nego tokens in challenge response")
	}

	ch, err := ParseNTLMChallenge(resp1.NegoTokens[0].NegoToken)
	if err != nil {
		return err
	}

	type3, err := GenerateNTLMAuthenticate(domain, user, password, ch)
	if err != nil {
		return err
	}

	req2 := TSRequest{
		Version: 2,
		NegoTokens: []NegoData{
			{NegoToken: type3},
		},
	}
	if err := writeTSRequest(conn, req2); err != nil {
		return err
	}

	resp2, err := readTSRequest(conn)
	if err != nil {
		if err == io.EOF {
			return &AuthError{NTStatus: StatusLogonFailure, Message: "authentication rejected by server"}
		}
		return err
	}

	if resp2.ErrorCode != 0 {
		return mapNTStatus(uint32(resp2.ErrorCode))
	}

	return nil
}

func mapNTStatus(code uint32) error {
	switch code {
	case StatusLogonFailure, StatusWrongPassword:
		return &AuthError{NTStatus: code, Message: "invalid credentials"}
	case StatusAccountLocked:
		return &AuthError{NTStatus: code, Message: "account is locked"}
	case StatusAccountDisabled:
		return &AuthError{NTStatus: code, Message: "account is disabled"}
	case StatusPasswordExpired:
		return &AuthError{NTStatus: code, Message: "password expired"}
	default:
		return &AuthError{NTStatus: code, Message: "authentication failed"}
	}
}

func writeTSRequest(w io.Writer, req TSRequest) error {
	data, err := asn1.Marshal(req)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func readTSRequest(r io.Reader) (*TSRequest, error) {
	var tag [2]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return nil, err
	}
	if tag[0] != 0x30 {
		return nil, fmt.Errorf("credssp: expected ASN.1 sequence (0x30), got 0x%02X", tag[0])
	}

	var length int
	if tag[1] < 0x80 {
		length = int(tag[1])
	} else {
		numBytes := int(tag[1] & 0x7f)
		if numBytes > 4 {
			return nil, fmt.Errorf("credssp: invalid ASN.1 length")
		}
		lenBuf := make([]byte, numBytes)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return nil, err
		}
		for _, b := range lenBuf {
			length = (length << 8) | int(b)
		}
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}

	fullPDU := append([]byte{tag[0], tag[1]}, body...)
	var req TSRequest
	if _, err := asn1.Unmarshal(fullPDU, &req); err != nil {
		if _, err2 := asn1.Unmarshal(body, &req); err2 != nil {
			return nil, err
		}
	}
	return &req, nil
}
