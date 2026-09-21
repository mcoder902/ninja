package remotego

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Protocol identifies the wire protocol a Target speaks.
type Protocol uint8

const (
	// ProtocolUnknown is the zero value; Target validation rejects it.
	ProtocolUnknown Protocol = iota
	// ProtocolSSH targets an SSH server (RFC 4251).
	ProtocolSSH
	// ProtocolRDP targets a Microsoft RDP server (MS-RDPBCGR).
	ProtocolRDP
)

// String implements fmt.Stringer for Protocol.
func (p Protocol) String() string {
	switch p {
	case ProtocolSSH:
		return "ssh"
	case ProtocolRDP:
		return "rdp"
	default:
		return "unknown"
	}
}

// DefaultPort returns the conventional TCP port for p, or 0 if unknown.
func (p Protocol) DefaultPort() int {
	switch p {
	case ProtocolSSH:
		return 22
	case ProtocolRDP:
		return 3389
	default:
		return 0
	}
}

// AuthMethodKind identifies the mechanism used to prove identity.
type AuthMethodKind uint8

const (
	// AuthMethodNone requests no authentication (protocol probing only).
	AuthMethodNone AuthMethodKind = iota
	// AuthMethodPassword authenticates with a username/password pair.
	AuthMethodPassword
	// AuthMethodPrivateKey authenticates with a public/private key pair
	// (SSH only; PEM or OpenSSH-formatted key material).
	AuthMethodPrivateKey
)

// String implements fmt.Stringer for AuthMethodKind.
func (k AuthMethodKind) String() string {
	switch k {
	case AuthMethodPassword:
		return "password"
	case AuthMethodPrivateKey:
		return "private_key"
	default:
		return "none"
	}
}

// AuthMethod describes how to authenticate against a Target. Exactly one
// of the fields relevant to Kind should be populated; Validate enforces
// this so misconfiguration is caught before any network I/O happens.
type AuthMethod struct {
	Kind AuthMethodKind

	// Username is required for AuthMethodPassword and AuthMethodPrivateKey.
	Username string

	// Password is required for AuthMethodPassword.
	Password string

	// PrivateKeyPEM holds PEM or OpenSSH-formatted private key bytes,
	// required for AuthMethodPrivateKey.
	PrivateKeyPEM []byte
	// PrivateKeyPassphrase decrypts PrivateKeyPEM if it is encrypted.
	// Leave empty for unencrypted keys.
	PrivateKeyPassphrase []byte
}

// Validate reports whether the AuthMethod is internally consistent.
func (a AuthMethod) Validate() error {
	switch a.Kind {
	case AuthMethodNone:
		return nil
	case AuthMethodPassword:
		if a.Username == "" {
			return fmt.Errorf("remotego: password auth requires a Username")
		}
		return nil
	case AuthMethodPrivateKey:
		if a.Username == "" {
			return fmt.Errorf("remotego: private key auth requires a Username")
		}
		if len(a.PrivateKeyPEM) == 0 {
			return fmt.Errorf("remotego: private key auth requires PrivateKeyPEM")
		}
		return nil
	default:
		return fmt.Errorf("remotego: unknown AuthMethodKind %d", a.Kind)
	}
}

// Password returns a password AuthMethod.
func Password(username, password string) AuthMethod {
	return AuthMethod{Kind: AuthMethodPassword, Username: username, Password: password}
}

// PrivateKey returns a private-key AuthMethod. passphrase may be nil for
// unencrypted keys.
func PrivateKey(username string, pemBytes, passphrase []byte) AuthMethod {
	return AuthMethod{
		Kind:                 AuthMethodPrivateKey,
		Username:             username,
		PrivateKeyPEM:        pemBytes,
		PrivateKeyPassphrase: passphrase,
	}
}

// NoAuth returns an AuthMethod requesting no authentication, for pure
// connectivity/banner probing.
func NoAuth() AuthMethod {
	return AuthMethod{Kind: AuthMethodNone}
}

// Target describes one remote endpoint to dial or probe.
type Target struct {
	// Host is a hostname or IP address, without a port.
	Host string
	// Port is the TCP port. If zero, Protocol.DefaultPort() is used.
	Port int
	// Protocol selects which dialer handles this target.
	Protocol Protocol
	// Auth describes how to authenticate. Zero value (AuthMethodNone)
	// performs an unauthenticated protocol probe only.
	Auth AuthMethod
	// Label is an opaque, developer-supplied identifier echoed back on
	// every Result for this target (e.g. an inventory ID). It has no
	// effect on dialing and is never sent over the wire.
	Label string
}

// Addr returns the "host:port" address to dial, applying the protocol's
// default port when Port is zero.
func (t Target) Addr() string {
	port := t.Port
	if port == 0 {
		port = t.Protocol.DefaultPort()
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

// Validate reports whether the Target is well-formed enough to attempt.
func (t Target) Validate() error {
	if t.Host == "" {
		return fmt.Errorf("remotego: target Host must not be empty")
	}
	if t.Protocol != ProtocolSSH && t.Protocol != ProtocolRDP {
		return fmt.Errorf("remotego: target Protocol must be ProtocolSSH or ProtocolRDP")
	}
	if t.Port < 0 || t.Port > 65535 {
		return fmt.Errorf("remotego: target Port %d out of range", t.Port)
	}
	if err := t.Auth.Validate(); err != nil {
		return err
	}
	return nil
}

// ProbeResult is the outcome of a Client.Probe call: it reports whether a
// target is reachable, speaks the expected protocol, and (if credentials
// were supplied) whether they were accepted — without leaving an active
// session open.
type ProbeResult struct {
	// Target is the target this result corresponds to.
	Target Target
	// Reachable reports whether a TCP connection was established at all.
	Reachable bool
	// ProtocolConfirmed reports whether the target was confirmed to speak
	// Target.Protocol (banner/handshake matched expectations).
	ProtocolConfirmed bool
	// AuthOK reports whether supplied credentials were accepted. It is
	// always false when Target.Auth.Kind is AuthMethodNone, since no
	// auth was attempted.
	AuthOK bool
	// Banner holds the raw protocol banner/identification string, when
	// the protocol exposes one (e.g. SSH's "SSH-2.0-..." line).
	Banner string
	// ServerVersion holds a parsed, human-readable server software
	// version when it can be extracted from Banner.
	ServerVersion string
	// Latency is the total wall-clock time the probe took, including
	// retries and backoff waits.
	Latency time.Duration
	// Attempts is how many attempts were made (1 unless retries occurred).
	Attempts int
	// Err holds the classification of what went wrong, or nil on full
	// success. It is always either nil or a *RemoteError.
	Err error
}

// Success reports whether the probe fully succeeded: reachable, protocol
// confirmed, and (if credentials were supplied) authenticated.
func (r ProbeResult) Success() bool {
	return r.Err == nil && r.Reachable && r.ProtocolConfirmed
}

// SessionState reports the lifecycle state of a Session.
type SessionState uint8

const (
	// SessionStateConnecting indicates the session is still establishing
	// its transport, protocol handshake, or authentication.
	SessionStateConnecting SessionState = iota
	// SessionStateActive indicates the session is authenticated and
	// ready for use.
	SessionStateActive
	// SessionStateClosed indicates the session has been closed, either
	// by the caller or by the remote end / an underlying I/O error.
	SessionStateClosed
)

// String implements fmt.Stringer for SessionState.
func (s SessionState) String() string {
	switch s {
	case SessionStateConnecting:
		return "connecting"
	case SessionStateActive:
		return "active"
	case SessionStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Session is the contract every active connection returned by Client.Dial
// implements, regardless of underlying protocol. It gives callers a
// uniform way to execute commands, open tunnels, and manage lifecycle,
// while protocol-specific capabilities remain reachable via type
// assertions on the concrete type (*SSHSession, *RDPSession) or the
// narrower capability interfaces below.
type Session interface {
	io.Closer

	// Target returns the Target this session is connected to.
	Target() Target
	// State returns the session's current lifecycle state.
	State() SessionState
	// Protocol returns the protocol this session speaks.
	Protocol() Protocol
}

// CommandExecutor is implemented by sessions that can run a single
// non-interactive command and capture its output (SSH's "exec" channel
// type). RDP sessions do not implement this interface.
type CommandExecutor interface {
	// Exec runs cmd and returns its combined stdout; a non-zero remote
	// exit status is surfaced as an error via errors.As into *RemoteError
	// with Detail describing the exit status, not as a Go panic or a
	// silently-empty result.
	Exec(ctx context.Context, cmd string) ([]byte, error)
}

// TunnelDialer is implemented by sessions that can open an additional
// logical stream multiplexed over the existing connection, for port
// forwarding / tunneling use cases (SSH direct-tcpip channels). RDP
// sessions expose their negotiated transport stream directly instead.
type TunnelDialer interface {
	// DialTunnel opens a new stream to network/addr as seen from the
	// remote side of the session (e.g. "tcp", "127.0.0.1:5432" for SSH
	// local-forwarding semantics).
	DialTunnel(ctx context.Context, network, addr string) (io.ReadWriteCloser, error)
}
