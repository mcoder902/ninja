package remotego

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHSession is an authenticated SSH connection. It implements Session,
// CommandExecutor and TunnelDialer.
type SSHSession struct {
	target Target
	client *ssh.Client
	state  atomic.Uint32
	once   sync.Once
	// ServerVersion is the server's SSH identification string.
	serverVersion string
}

var (
	_ Session         = (*SSHSession)(nil)
	_ CommandExecutor = (*SSHSession)(nil)
	_ TunnelDialer    = (*SSHSession)(nil)
)

// Target implements Session.
func (s *SSHSession) Target() Target { return s.target }

// Protocol implements Session.
func (s *SSHSession) Protocol() Protocol { return ProtocolSSH }

// State implements Session.
func (s *SSHSession) State() SessionState { return SessionState(s.state.Load()) }

// ServerVersion returns the server's identification string, e.g.
// "SSH-2.0-OpenSSH_9.6".
func (s *SSHSession) ServerVersion() string { return s.serverVersion }

// Client exposes the underlying *ssh.Client for capabilities beyond this
// package's contracts (SFTP, reverse forwarding, ...).
func (s *SSHSession) Client() *ssh.Client { return s.client }

// Close implements io.Closer. It is idempotent.
func (s *SSHSession) Close() error {
	var err error
	s.once.Do(func() {
		s.state.Store(uint32(SessionStateClosed))
		err = s.client.Close()
	})
	return err
}

// Exec implements CommandExecutor. It returns the command's combined
// stdout/stderr. A non-zero exit status yields a *RemoteError with
// ErrCodeCommandFailed alongside whatever output was produced.
func (s *SSHSession) Exec(ctx context.Context, cmd string) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = panicToError(s.target.Addr(), r, "")
		}
	}()
	if s.State() == SessionStateClosed {
		return nil, NewError(ErrCodeConnectionReset, s.target.Addr(), net.ErrClosed)
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return nil, ClassifyNetError(s.target.Addr(), err)
	}
	defer sess.Close()

	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- panicToError(s.target.Addr(), r, "")
			}
		}()
		done <- sess.Run(cmd)
	}()

	select {
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		_ = sess.Close()
		return nil, ClassifyNetError(s.target.Addr(), ctx.Err())
	case runErr := <-done:
		if runErr == nil {
			return buf.Bytes(), nil
		}
		var exit *ssh.ExitError
		if errors.As(runErr, &exit) {
			e := NewError(ErrCodeCommandFailed, s.target.Addr(), runErr)
			e.Detail = "exit status " + strconv.Itoa(exit.ExitStatus())
			return buf.Bytes(), e
		}
		if re, ok := AsRemoteError(runErr); ok {
			return buf.Bytes(), re
		}
		return buf.Bytes(), ClassifyNetError(s.target.Addr(), runErr)
	}
}

// DialTunnel implements TunnelDialer using an SSH direct-tcpip channel.
func (s *SSHSession) DialTunnel(ctx context.Context, network, addr string) (io.ReadWriteCloser, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- res{err: panicToError(s.target.Addr(), r, "")}
			}
		}()
		c, err := s.client.Dial(network, addr)
		ch <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		go func() { // reclaim a late-arriving connection
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, ClassifyNetError(s.target.Addr(), ctx.Err())
	case r := <-ch:
		if r.err != nil {
			if re, ok := AsRemoteError(r.err); ok {
				return nil, re
			}
			return nil, ClassifyNetError(s.target.Addr(), r.err)
		}
		return r.c, nil
	}
}

// sniffConn records the first bytes the peer sends so that, on handshake
// failure, we can tell "not SSH at all" apart from "SSH but failed".
type sniffConn struct {
	net.Conn
	mu  sync.Mutex
	buf [256]byte
	n   int
}

func (c *sniffConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.mu.Lock()
		if c.n < len(c.buf) {
			c.n += copy(c.buf[c.n:], p[:n])
		}
		c.mu.Unlock()
	}
	return n, err
}

// firstLine returns the bytes received so far up to the first newline.
func (c *sniffConn) firstLine() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf[:c.n]
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return strings.TrimRight(string(b), "\r")
}

func (c *sniffConn) received() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// authState tracks which authentication mechanisms were actually
// exercised, enabling precise post-mortem classification.
type authState struct {
	passwordTried atomic.Bool
	keyTried      atomic.Bool
	kbdTried      atomic.Bool
	mfaPrompted   atomic.Bool
	bannerMu      sync.Mutex
	banner        strings.Builder
}

func (a *authState) addBanner(msg string) {
	a.bannerMu.Lock()
	if a.banner.Len() < 4096 {
		a.banner.WriteString(msg)
	}
	a.bannerMu.Unlock()
}

func (a *authState) bannerText() string {
	a.bannerMu.Lock()
	defer a.bannerMu.Unlock()
	return a.banner.String()
}

var errMFAPrompt = errors.New("remotego: server requested an additional authentication factor")
var errAlreadyTried = errors.New("remotego: credential already submitted; refusing to resubmit")

// buildSSHAuth translates an AuthMethod into ssh auth methods plus tracking
// state. Each secret is submitted at most once per attempt to keep the
// lockout footprint minimal.
func buildSSHAuth(a AuthMethod, st *authState) ([]ssh.AuthMethod, error) {
	switch a.Kind {
	case AuthMethodNone:
		return nil, nil
	case AuthMethodPassword:
		pw := a.Password
		return []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) {
				st.passwordTried.Store(true)
				return pw, nil
			}),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				if len(questions) == 0 {
					return nil, nil
				}
				if len(questions) == 1 && !echos[0] && strings.Contains(strings.ToLower(questions[0]), "password") {
					if st.passwordTried.Load() || !st.kbdTried.CompareAndSwap(false, true) {
						return nil, errAlreadyTried
					}
					return []string{pw}, nil
				}
				st.mfaPrompted.Store(true)
				return nil, errMFAPrompt
			}),
		}, nil
	case AuthMethodPrivateKey:
		var signer ssh.Signer
		var err error
		if len(a.PrivateKeyPassphrase) > 0 {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(a.PrivateKeyPEM, a.PrivateKeyPassphrase)
		} else {
			signer, err = ssh.ParsePrivateKey(a.PrivateKeyPEM)
		}
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{
			ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
				st.keyTried.Store(true)
				return []ssh.Signer{signer}, nil
			}),
		}, nil
	default:
		return nil, errors.New("remotego: unsupported auth method")
	}
}

var lockoutPhrases = []string{
	"account is locked", "account locked", "account has been locked",
	"locked out", "account is disabled", "account disabled",
	"account has been disabled", "too many failed",
}

func looksLocked(s string) bool {
	s = strings.ToLower(s)
	for _, p := range lockoutPhrases {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// sshOutcome is the result of one SSH connection attempt.
type sshOutcome struct {
	client    *ssh.Client
	banner    string // server identification string
	reachable bool
	confirmed bool
	authOK    bool
	err       error
}

// sshConnect dials, handshakes and (optionally) authenticates. On success
// with a non-nil client, the caller owns it. It classifies every failure
// into a *RemoteError.
func (c *Client) sshConnect(ctx context.Context, t Target) (out sshOutcome) {
	addr := t.Addr()
	raw, err := c.dialTCP(ctx, t)
	if err != nil {
		out.err = err
		return out
	}
	out.reachable = true
	conn := &sniffConn{Conn: raw}

	st := &authState{}
	methods, kerr := buildSSHAuth(t.Auth, st)
	if kerr != nil {
		_ = raw.Close()
		ke := NewErrorf(ErrCodeKeyRejected, addr, kerr, "private key could not be parsed")
		ke.Retryable = false
		out.err = ke
		return out
	}

	hk := c.cfg.HostKeyCallback
	if hk == nil {
		hk = ssh.InsecureIgnoreHostKey() //nolint:gosec // documented opt-out; see WithHostKeyCallback
	}
	user := t.Auth.Username
	if user == "" {
		user = "remotego-probe"
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: hk,
		BannerCallback: func(msg string) error {
			st.addBanner(msg)
			return nil
		},
		Timeout: c.cfg.HandshakeTimeout + c.cfg.AuthTimeout,
	}

	// Bound the whole handshake+auth by deadline and by ctx.
	if total := c.cfg.HandshakeTimeout + c.cfg.AuthTimeout; total > 0 {
		_ = conn.SetDeadline(time.Now().Add(total))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })

	sc, chans, reqs, herr := ssh.NewClientConn(conn, addr, cfg)
	fired := !stop() // true if ctx ended and the close callback ran
	if herr != nil {
		_ = conn.Close()
		out.banner = conn.firstLine()
		if cerr := ctx.Err(); cerr != nil && fired {
			out.err = ClassifyNetError(addr, cerr)
			return out
		}
		out.err, out.confirmed = classifySSHError(addr, herr, t, conn, st)
		if out.confirmed && t.Auth.Kind == AuthMethodNone && isNoAuthResult(herr) {
			// Unauthenticated probe: the server completed key exchange and
			// merely refused "none" — exactly the outcome we wanted.
			out.err = nil
		}
		return out
	}
	if fired && ctx.Err() != nil {
		_ = sc.Close()
		out.err = ClassifyNetError(addr, ctx.Err())
		return out
	}
	_ = conn.SetDeadline(time.Time{})

	out.confirmed = true
	out.authOK = t.Auth.Kind != AuthMethodNone
	out.banner = string(sc.ServerVersion())
	out.client = ssh.NewClient(sc, chans, reqs)
	return out
}

func isNoAuthResult(err error) bool {
	return strings.Contains(err.Error(), "unable to authenticate")
}

// classifySSHError maps an ssh.NewClientConn failure onto the taxonomy. The
// bool reports whether the peer was positively identified as an SSH server.
func classifySSHError(addr string, err error, t Target, conn *sniffConn, st *authState) (*RemoteError, bool) {
	line := conn.firstLine()
	isSSH := strings.HasPrefix(line, "SSH-")
	msg := err.Error()

	// 1. Nothing (or non-SSH) on the wire.
	if !isSSH {
		if conn.received() > 0 {
			e := NewErrorf(ErrCodeProtocolMismatch, addr, err, "target is not an SSH server")
			e.Detail = "first bytes: " + printable(line, 48)
			e.Retryable = false
			return e, false
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return NewError(ErrCodeConnectionReset, addr, err), false
		}
		return ClassifyNetError(addr, err), false
	}

	// 2. Peer is SSH. Authentication outcomes.
	if st.mfaPrompted.Load() || errors.Is(err, errMFAPrompt) {
		e := NewError(ErrCodeMFAChallengeRequired, addr, err)
		return e, true
	}
	if looksLocked(msg) || looksLocked(st.bannerText()) {
		return NewError(ErrCodeAccountLocked, addr, err), true
	}
	if strings.Contains(msg, "unable to authenticate") {
		switch t.Auth.Kind {
		case AuthMethodPassword:
			if !st.passwordTried.Load() && !st.kbdTried.Load() {
				e := NewErrorf(ErrCodeUnsupportedAuthMethod, addr, err, "server does not offer password authentication")
				return e, true
			}
			return NewError(ErrCodeInvalidCredentials, addr, err), true
		case AuthMethodPrivateKey:
			if !st.keyTried.Load() {
				return NewErrorf(ErrCodeUnsupportedAuthMethod, addr, err, "server does not offer public key authentication"), true
			}
			return NewError(ErrCodeKeyRejected, addr, err), true
		default:
			// AuthMethodNone: server refused "none"; caller treats as ok.
			return NewError(ErrCodeInvalidCredentials, addr, err), true
		}
	}

	// 3. Protocol-level handshake problems on a genuine SSH peer.
	if strings.Contains(msg, "no common algorithm") {
		e := NewErrorf(ErrCodeHandshakeCorrupted, addr, err, "no mutually supported SSH algorithms")
		e.Retryable = false
		return e, true
	}
	var ne net.Error
	if errors.As(err, &ne) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		re := ClassifyNetError(addr, err)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			re = NewErrorf(ErrCodeHandshakeCorrupted, addr, err, "connection closed during SSH handshake")
		}
		return re, true
	}
	if strings.Contains(msg, "ssh: disconnect") {
		return NewErrorf(ErrCodeHandshakeCorrupted, addr, err, "server disconnected during handshake"), true
	}
	return NewError(ErrCodeHandshakeCorrupted, addr, err), true
}

// printable renders up to n bytes of s with non-printables replaced, safe
// for embedding in error details.
func printable(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	b := []byte(s)
	for i, ch := range b {
		if ch < 0x20 || ch > 0x7e {
			b[i] = '.'
		}
	}
	return string(b)
}
