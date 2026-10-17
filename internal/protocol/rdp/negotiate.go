package rdp

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"time"
)

type Options struct {
	Offer              SecurityProtocol
	Cookie             string
	ServerName         string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

type Negotiation struct {
	Conn               net.Conn
	Selected           SecurityProtocol
	NegotiationPresent bool
	TLSVersion         uint16
	PeerCertSubject    string
	ServerPubKey       []byte
}

type FailureError struct {
	Code FailureCode
}

func (e *FailureError) Error() string { return "rdp: negotiation failed: " + e.Code.String() }

type TLSError struct {
	Err error
}

func (e *TLSError) Error() string { return "rdp: TLS handshake failed: " + e.Err.Error() }
func (e *TLSError) Unwrap() error { return e.Err }

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func Negotiate(ctx context.Context, conn net.Conn, opts Options) (*Negotiation, error) {
	offer := opts.Offer
	if offer == 0 {
		offer = ProtoSSL
	}

	stop := watchContext(ctx, conn)
	defer stop()

	if opts.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		defer func() {
			_ = conn.SetDeadline(time.Time{})
		}()
	}

	if err := WriteConnectionRequest(conn, opts.Cookie, offer); err != nil {
		return nil, ctxErrOr(ctx, err)
	}

	payload, err := ReadTPKT(conn)
	if err != nil {
		return nil, ctxErrOr(ctx, err)
	}
	defer PutBuffer(payload)

	cc, err := ParseConnectionConfirm(payload)
	if err != nil {
		return nil, err
	}
	if cc.Failed {
		return nil, &FailureError{Code: cc.FailureCode}
	}

	neg := &Negotiation{
		Conn:               conn,
		Selected:           cc.Selected,
		NegotiationPresent: cc.NegotiationPresent,
	}

	if cc.Selected&(ProtoSSL|ProtoHybrid|ProtoHybridEx|ProtoRDSTLS) != 0 {
		var suites []uint16
		for _, cs := range tls.CipherSuites() {
			suites = append(suites, cs.ID)
		}
		for _, cs := range tls.InsecureCipherSuites() {
			suites = append(suites, cs.ID)
		}

		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			CipherSuites:       suites,
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, &TLSError{Err: ctxErrOr(ctx, err)}
		}
		state := tc.ConnectionState()
		neg.Conn = tc
		neg.TLSVersion = state.Version
		if len(state.PeerCertificates) > 0 {
			leaf := state.PeerCertificates[0]
			neg.PeerCertSubject = leaf.Subject.String()
			var spki subjectPublicKeyInfo
			if _, err := asn1.Unmarshal(leaf.RawSubjectPublicKeyInfo, &spki); err == nil {
				neg.ServerPubKey = spki.SubjectPublicKey.Bytes
			}
		}
	}

	return neg, nil
}

func watchContext(ctx context.Context, conn net.Conn) (stop func()) {
	if ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Unix(1, 0))
		case <-done:
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

func ctxErrOr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return cerr
	}
	return err
}
