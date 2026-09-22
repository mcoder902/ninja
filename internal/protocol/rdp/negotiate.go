package rdp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// Options controls a Negotiate call.
type Options struct {
	// Offer is the set of security protocols to offer the server.
	// Zero means offer TLS only (ProtoSSL).
	Offer SecurityProtocol
	// Cookie is an optional routing token line ("mstshash=...").
	Cookie string
	// ServerName is used for TLS SNI/verification when TLS is negotiated.
	ServerName string
	// InsecureSkipVerify disables TLS certificate verification. RDP
	// servers overwhelmingly present self-signed certificates, so
	// callers frequently need this.
	InsecureSkipVerify bool
	// Timeout bounds each blocking phase (negotiation and TLS handshake).
	// Zero means rely solely on ctx.
	Timeout time.Duration
}

// Negotiation is the outcome of a successful Negotiate.
type Negotiation struct {
	// Conn is the connection to use from here on. If TLS was selected it
	// is the *tls.Conn wrapping the original connection.
	Conn net.Conn
	// Selected is the security protocol the server chose.
	Selected SecurityProtocol
	// NegotiationPresent mirrors ConnectionConfirm.NegotiationPresent.
	NegotiationPresent bool
	// TLSVersion is the negotiated TLS version when Conn is a TLS
	// connection, else zero.
	TLSVersion uint16
	// PeerCertSubject is the leaf certificate subject when TLS was used.
	PeerCertSubject string
}

// FailureError is returned when the server answered with a well-formed RDP
// Negotiation Failure PDU. It proves the peer is a real RDP server.
type FailureError struct {
	Code FailureCode
}

func (e *FailureError) Error() string { return "rdp: negotiation failed: " + e.Code.String() }

// TLSError wraps a failure of the TLS handshake after the server agreed to
// TLS-based security.
type TLSError struct {
	Err error
}

func (e *TLSError) Error() string { return "rdp: TLS handshake failed: " + e.Err.Error() }
func (e *TLSError) Unwrap() error { return e.Err }

// Negotiate performs the X.224 connection request/confirm exchange over
// conn and, if the server selects a TLS-based protocol, upgrades conn to
// TLS. It honors ctx for cancellation by setting connection deadlines and
// closing the deadline watcher on return.
//
// Errors:
//   - *MalformedError: peer bytes are not valid RDP negotiation data
//     (NotRDP distinguishes "not RDP at all" from "RDP-shaped but broken").
//   - *FailureError: server sent a Negotiation Failure PDU.
//   - *TLSError: TLS upgrade failed.
//   - any other error: underlying I/O error (timeouts, resets, EOF).
func Negotiate(ctx context.Context, conn net.Conn, opts Options) (*Negotiation, error) {
	offer := opts.Offer
	if offer == 0 {
		offer = ProtoSSL
	}

	stop := watchContext(ctx, conn)
	defer stop()

	if opts.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
		defer func(conn net.Conn, t time.Time) {
			err := conn.SetDeadline(t)
			if err != nil {

			}
		}(conn, time.Time{}) //nolint:errcheck
	}

	if err := WriteConnectionRequest(conn, opts.Cookie, offer); err != nil {
		return nil, ctxErrOr(ctx, err)
	}
	payload, err := ReadTPKT(conn)
	if err != nil {
		return nil, ctxErrOr(ctx, err)
	}
	cc, err := ParseConnectionConfirm(payload)
	if err != nil {
		return nil, err
	}
	if cc.Failed {
		return nil, &FailureError{Code: cc.FailureCode}
	}

	neg := &Negotiation{Conn: conn, Selected: cc.Selected, NegotiationPresent: cc.NegotiationPresent}

	if cc.Selected&(ProtoSSL|ProtoHybrid|ProtoHybridEx|ProtoRDSTLS) != 0 {
		cfg := &tls.Config{
			ServerName:         opts.ServerName,
			InsecureSkipVerify: opts.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS10,
		}
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, &TLSError{Err: ctxErrOr(ctx, err)}
		}
		state := tc.ConnectionState()
		neg.Conn = tc
		neg.TLSVersion = state.Version
		if len(state.PeerCertificates) > 0 {
			neg.PeerCertSubject = state.PeerCertificates[0].Subject.String()
		}
	}
	return neg, nil
}

// watchContext arranges for blocked I/O on conn to be interrupted when ctx
// is canceled, by forcing an immediate deadline. The returned function
// stops the watcher and must be called before returning.
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

// ctxErrOr returns ctx.Err() if the context is done (the I/O error was then
// almost certainly caused by our forced deadline), else err.
func ctxErrOr(ctx context.Context, err error) error {
	if cerr := ctx.Err(); cerr != nil && !errors.Is(err, cerr) {
		return cerr
	}
	return err
}
