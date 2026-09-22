package remotego

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mcoder902/ninja/internal/protocol/rdp"
)

type RDPSession struct {
	target   Target
	conn     net.Conn
	selected rdp.SecurityProtocol
	certSubj string
	state    atomic.Uint32
	once     sync.Once
}

var _ Session = (*RDPSession)(nil)

func (s *RDPSession) Target() Target                 { return s.target }
func (s *RDPSession) Protocol() Protocol             { return ProtocolRDP }
func (s *RDPSession) State() SessionState            { return SessionState(s.state.Load()) }
func (s *RDPSession) Conn() io.ReadWriteCloser       { return s.conn }
func (s *RDPSession) SecurityProtocol() string       { return s.selected.String() }
func (s *RDPSession) PeerCertificateSubject() string { return s.certSubj }

func (s *RDPSession) Close() error {
	var err error
	s.once.Do(func() {
		s.state.Store(uint32(SessionStateClosed))
		err = s.conn.Close()
	})
	return err
}

type rdpOutcome struct {
	neg       *rdp.Negotiation
	reachable bool
	confirmed bool
	authOK    bool
	banner    string
	err       error
}

func (c *Client) rdpConnect(ctx context.Context, t Target, probe bool) (out rdpOutcome) {
	addr := t.Addr()

	// انتشار رویداد: شروع اتصال TCP[cite: 6]
	c.emitEvent(t, EventDialing, "initiating RDP TCP connection")
	conn, err := c.dialTCP(ctx, t)
	if err != nil {
		c.emitEvent(t, EventFailed, err.Error())
		out.err = err
		return out
	}
	c.emitEvent(t, EventConnected, "RDP TCP connection established")
	out.reachable = true

	// انتشار رویداد: شروع هندشیک و مذاکره پروتکل[cite: 6]
	c.emitEvent(t, EventHandshaking, "negotiating RDP security protocols")
	offer := rdp.ProtoSSL | rdp.ProtoHybrid | rdp.ProtoHybridEx
	neg, nerr := rdp.Negotiate(ctx, conn, rdp.Options{
		Offer:              offer,
		ServerName:         t.Host,
		InsecureSkipVerify: c.cfg.InsecureSkipTLSVerify,
		Timeout:            c.cfg.HandshakeTimeout,
	})
	if nerr != nil {
		_ = conn.Close()
		out.err, out.confirmed, out.banner = classifyRDPError(addr, nerr)
		c.emitEvent(t, EventFailed, out.err.Error())
		return out
	}

	out.neg = neg
	out.confirmed = true
	out.banner = neg.Selected.String()

	if t.Auth.Kind == AuthMethodPassword {
		domain := ""
		user := t.Auth.Username
		if parts := strings.SplitN(user, "\\", 2); len(parts) == 2 {
			domain = parts[0]
			user = parts[1]
		}

		// انتشار رویداد: شروع احراز هویت CredSSP[cite: 6]
		c.emitEvent(t, EventAuthenticating, "submitting CredSSP credentials")
		if total := c.cfg.AuthTimeout; total > 0 {
			_ = neg.Conn.SetDeadline(time.Now().Add(total))
		}
		stop := context.AfterFunc(ctx, func() {
			_ = neg.Conn.Close()
		})
		defer stop()
		aerr := rdp.AuthenticateCredSSP(ctx, neg.Conn, domain, user, t.Auth.Password)
		_ = neg.Conn.SetDeadline(time.Time{})
		if aerr != nil {
			var authErr *rdp.AuthError
			if errors.As(aerr, &authErr) {
				switch authErr.NTStatus {
				case rdp.StatusLogonFailure, rdp.StatusWrongPassword:
					out.err = NewError(ErrCodeInvalidCredentials, addr, aerr)
				case rdp.StatusAccountLocked, rdp.StatusAccountDisabled:
					out.err = NewError(ErrCodeAccountLocked, addr, aerr)
				default:
					out.err = NewError(ErrCodeInvalidCredentials, addr, aerr)
				}
			} else {
				out.err = ClassifyNetError(addr, aerr)
			}
			c.emitEvent(t, EventFailed, out.err.Error())
			return out
		}
		out.authOK = true
	}

	c.emitEvent(t, EventSuccess, "RDP probe/authentication succeeded")
	return out
}

func classifyRDPError(addr string, err error) (*RemoteError, bool, string) {
	var mal *rdp.MalformedError
	var fail *rdp.FailureError
	var tlsErr *rdp.TLSError

	switch {
	case errors.As(err, &mal):
		if mal.NotRDP {
			e := NewErrorf(ErrCodeProtocolMismatch, addr, err, "target is not an RDP server")
			e.Retryable = false
			return e, false, ""
		}
		return NewError(ErrCodeHandshakeCorrupted, addr, err), false, ""
	case errors.As(err, &fail):
		desc := fail.Code.String()
		e := NewErrorf(ErrCodeTLSFailure, addr, err, "RDP security negotiation rejected: %s", desc)
		e.Retryable = false
		return e, true, desc
	case errors.As(err, &tlsErr):
		var ne net.Error
		if errors.Is(tlsErr.Err, context.Canceled) || errors.Is(tlsErr.Err, context.DeadlineExceeded) || (errors.As(tlsErr.Err, &ne) && ne.Timeout()) {
			return ClassifyNetError(addr, tlsErr.Err), true, ""
		}
		return NewError(ErrCodeTLSFailure, addr, err), true, ""
	case errors.Is(err, io.EOF):
		return NewErrorf(ErrCodeConnectionReset, addr, err, "connection closed during RDP negotiation"), false, ""
	case errors.Is(err, io.ErrUnexpectedEOF):
		return NewError(ErrCodeHandshakeCorrupted, addr, err), false, ""
	default:
		return ClassifyNetError(addr, err), false, ""
	}
}
