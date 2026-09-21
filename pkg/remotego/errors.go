// Package remotego provides a high-concurrency, pure-Go SDK for probing and
// driving SSH and RDP connections against large fleets of remote targets.
//
// errors.go defines the library's structured error taxonomy. Every failure
// surfaced across package boundaries is a *RemoteError carrying a stable
// ErrorCode, a Phase (Network/Protocol/Auth), the offending Target, and the
// underlying cause (via error wrapping, compatible with errors.Is/As).
package remotego

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
)

// Phase identifies which stage of a connection attempt produced an error.
// Callers can use it to decide, at a glance, whether a failure happened
// before a protocol was even spoken (Network), while speaking the wire
// protocol (Protocol), or while proving identity (Auth).
type Phase uint8

const (
	// PhaseUnknown is the zero value; it should not appear on a properly
	// constructed RemoteError but is defined so switches can be exhaustive.
	PhaseUnknown Phase = iota
	// PhaseNetwork covers L3/L4 failures: DNS, TCP dial, timeouts, resets.
	PhaseNetwork
	// PhaseProtocol covers L7 wire-protocol failures: banner mismatches,
	// malformed handshakes, TLS negotiation failures.
	PhaseProtocol
	// PhaseAuth covers identity/authorization failures after a valid
	// protocol handshake has completed.
	PhaseAuth
	// PhaseInternal covers defects inside the library itself, including
	// recovered panics, as well as caller-side misuse (bad configuration,
	// cancellation). These should never be silently swallowed.
	PhaseInternal
	// PhaseSession covers failures of an operation on an already
	// established, authenticated session (e.g. a remote command failing).
	PhaseSession
)

// String implements fmt.Stringer for Phase.
func (p Phase) String() string {
	switch p {
	case PhaseNetwork:
		return "network"
	case PhaseProtocol:
		return "protocol"
	case PhaseAuth:
		return "auth"
	case PhaseInternal:
		return "internal"
	case PhaseSession:
		return "session"
	default:
		return "unknown"
	}
}

// ErrorCode is a stable, comparable identifier for a specific failure mode.
// Codes are grouped by Phase in contiguous ranges purely for readability;
// callers must not rely on numeric ordering, only on the named constants.
type ErrorCode uint32

const (
	// ErrCodeUnknown is the zero value for ErrorCode.
	ErrCodeUnknown ErrorCode = iota

	// --- Network / L4 -------------------------------------------------

	// ErrCodeTimeout indicates the operation exceeded its deadline before
	// completing (dial, handshake, or auth all use this uniformly at the
	// network layer; protocol/auth-specific timeouts still surface here
	// when the underlying cause is a plain I/O deadline).
	ErrCodeTimeout
	// ErrCodeHostUnreachable indicates the network stack could not route
	// to the target host (ICMP unreachable, no route to host).
	ErrCodeHostUnreachable
	// ErrCodeConnectionRefused indicates the target actively refused the
	// TCP connection (RST on SYN), typically meaning nothing is listening
	// on the given port.
	ErrCodeConnectionRefused
	// ErrCodeDNSResolutionFailed indicates the target hostname could not
	// be resolved to an address.
	ErrCodeDNSResolutionFailed
	// ErrCodeSocketExhaustion indicates the local or remote OS has run out
	// of socket resources (EMFILE, ENFILE, WSAENOBUFS, ephemeral port
	// exhaustion). This is a resource-pressure signal, not a target fault.
	ErrCodeSocketExhaustion
	// ErrCodeConnectionReset indicates the connection was reset by the
	// peer after being established (RST mid-session, ECONNRESET).
	ErrCodeConnectionReset
	// ErrCodeNetworkUnreachable indicates the local network stack has no
	// path to the destination network at all.
	ErrCodeNetworkUnreachable

	// --- Protocol / L7 -------------------------------------------------

	// ErrCodeProtocolMismatch indicates the target does not speak the
	// protocol the caller requested (e.g. dialing SSH against an HTTP
	// server, or RDP against a plain TCP echo service).
	ErrCodeProtocolMismatch
	// ErrCodeHandshakeCorrupted indicates the target speaks the right
	// protocol family but sent a malformed, truncated, or otherwise
	// unparseable handshake message.
	ErrCodeHandshakeCorrupted
	// ErrCodeTLSFailure indicates a TLS/SSL negotiation failure during a
	// protocol handshake that requires or upgrades to TLS (RDP PROTOCOL_SSL,
	// SSH-over-TLS proxies, etc.).
	ErrCodeTLSFailure
	// ErrCodeUnsupportedAuthMethod indicates the target requires an
	// authentication/security mechanism this library does not implement
	// (for example RDP CredSSP/NLA full credential exchange). This is
	// deliberately distinct from InvalidCredentials: it means "we cannot
	// even attempt to prove identity here," not "identity was rejected."
	ErrCodeUnsupportedAuthMethod

	// --- Auth ------------------------------------------------------------

	// ErrCodeInvalidCredentials indicates the target explicitly rejected
	// the supplied username/password or username/key pair as wrong.
	ErrCodeInvalidCredentials
	// ErrCodeKeyRejected indicates a public/private key was structurally
	// valid but rejected by the target (not authorized, wrong key type,
	// or revoked).
	ErrCodeKeyRejected
	// ErrCodeAccountLocked indicates the target reports the account is
	// locked, disabled, or otherwise administratively blocked, independent
	// of whether the credentials themselves were correct.
	ErrCodeAccountLocked
	// ErrCodeMFAChallengeRequired indicates the target demands an
	// additional interactive/MFA factor this library was not configured
	// (or able) to satisfy.
	ErrCodeMFAChallengeRequired
	// ErrCodeAuthTimeout indicates the auth exchange itself timed out
	// (distinct from a network-level dial timeout).
	ErrCodeAuthTimeout

	// --- Internal / control -------------------------------------------

	// ErrCodePanicRecovered indicates a goroutine inside the library
	// panicked and was recovered at an isolation boundary. The original
	// panic value and a stack trace are preserved in the error's Detail.
	ErrCodePanicRecovered
	// ErrCodeContextCanceled indicates the caller's context was canceled
	// or exceeded its deadline before the operation completed.
	ErrCodeContextCanceled
	// ErrCodeClientClosed indicates the operation was attempted on (or
	// interrupted by the closing of) a Client that has been shut down.
	ErrCodeClientClosed
	// ErrCodeInvalidTarget indicates the Target or its auth configuration
	// failed validation before any network I/O was attempted.
	ErrCodeInvalidTarget

	// --- Session -----------------------------------------------------

	// ErrCodeCommandFailed indicates a remote command ran but exited with
	// a non-zero status or was terminated by a signal. Detail carries the
	// exit status.
	ErrCodeCommandFailed
)

// String implements fmt.Stringer for ErrorCode, returning a stable
// machine-friendly identifier (also used in %v/%s formatting of RemoteError).
func (c ErrorCode) String() string {
	switch c {
	case ErrCodeTimeout:
		return "TIMEOUT"
	case ErrCodeHostUnreachable:
		return "HOST_UNREACHABLE"
	case ErrCodeConnectionRefused:
		return "CONNECTION_REFUSED"
	case ErrCodeDNSResolutionFailed:
		return "DNS_RESOLUTION_FAILED"
	case ErrCodeSocketExhaustion:
		return "SOCKET_EXHAUSTION"
	case ErrCodeConnectionReset:
		return "CONNECTION_RESET"
	case ErrCodeNetworkUnreachable:
		return "NETWORK_UNREACHABLE"
	case ErrCodeProtocolMismatch:
		return "PROTOCOL_MISMATCH"
	case ErrCodeHandshakeCorrupted:
		return "HANDSHAKE_CORRUPTED"
	case ErrCodeTLSFailure:
		return "TLS_FAILURE"
	case ErrCodeUnsupportedAuthMethod:
		return "UNSUPPORTED_AUTH_METHOD"
	case ErrCodeInvalidCredentials:
		return "INVALID_CREDENTIALS"
	case ErrCodeKeyRejected:
		return "KEY_REJECTED"
	case ErrCodeAccountLocked:
		return "ACCOUNT_LOCKED"
	case ErrCodeMFAChallengeRequired:
		return "MFA_CHALLENGE_REQUIRED"
	case ErrCodeAuthTimeout:
		return "AUTH_TIMEOUT"
	case ErrCodePanicRecovered:
		return "PANIC_RECOVERED"
	case ErrCodeContextCanceled:
		return "CONTEXT_CANCELED"
	case ErrCodeClientClosed:
		return "CLIENT_CLOSED"
	case ErrCodeInvalidTarget:
		return "INVALID_TARGET"
	case ErrCodeCommandFailed:
		return "COMMAND_FAILED"
	default:
		return "UNKNOWN"
	}
}

// phaseForCode returns the canonical Phase for a given ErrorCode so that
// constructors never need to pass a redundant, potentially inconsistent
// Phase alongside a code.
func phaseForCode(c ErrorCode) Phase {
	switch c {
	case ErrCodeTimeout, ErrCodeHostUnreachable, ErrCodeConnectionRefused,
		ErrCodeDNSResolutionFailed, ErrCodeSocketExhaustion,
		ErrCodeConnectionReset, ErrCodeNetworkUnreachable:
		return PhaseNetwork
	case ErrCodeProtocolMismatch, ErrCodeHandshakeCorrupted, ErrCodeTLSFailure,
		ErrCodeUnsupportedAuthMethod:
		return PhaseProtocol
	case ErrCodeInvalidCredentials, ErrCodeKeyRejected, ErrCodeAccountLocked,
		ErrCodeMFAChallengeRequired, ErrCodeAuthTimeout:
		return PhaseAuth
	case ErrCodePanicRecovered, ErrCodeContextCanceled, ErrCodeClientClosed,
		ErrCodeInvalidTarget:
		return PhaseInternal
	case ErrCodeCommandFailed:
		return PhaseSession
	default:
		return PhaseUnknown
	}
}

// humanMessage returns a stable, human-readable description for a code,
// used as the default Message when a constructor doesn't override it.
func humanMessage(c ErrorCode) string {
	switch c {
	case ErrCodeTimeout:
		return "operation timed out"
	case ErrCodeHostUnreachable:
		return "host is unreachable"
	case ErrCodeConnectionRefused:
		return "connection refused by target"
	case ErrCodeDNSResolutionFailed:
		return "DNS resolution failed"
	case ErrCodeSocketExhaustion:
		return "socket resources exhausted"
	case ErrCodeConnectionReset:
		return "connection reset by peer"
	case ErrCodeNetworkUnreachable:
		return "network is unreachable"
	case ErrCodeProtocolMismatch:
		return "target does not speak the requested protocol"
	case ErrCodeHandshakeCorrupted:
		return "protocol handshake was malformed or corrupted"
	case ErrCodeTLSFailure:
		return "TLS negotiation failed"
	case ErrCodeUnsupportedAuthMethod:
		return "target requires an authentication method this library does not implement"
	case ErrCodeInvalidCredentials:
		return "invalid username or password"
	case ErrCodeKeyRejected:
		return "public/private key was rejected"
	case ErrCodeAccountLocked:
		return "account is locked or disabled"
	case ErrCodeMFAChallengeRequired:
		return "target requires an additional authentication factor"
	case ErrCodeAuthTimeout:
		return "authentication exchange timed out"
	case ErrCodePanicRecovered:
		return "internal panic was recovered"
	case ErrCodeContextCanceled:
		return "context was canceled"
	case ErrCodeClientClosed:
		return "client has been closed"
	case ErrCodeInvalidTarget:
		return "target configuration is invalid"
	case ErrCodeCommandFailed:
		return "remote command failed"
	default:
		return "unknown error"
	}
}

// RemoteError is the single structured error type returned across all
// package boundaries in remotego. It is designed to be inspected
// programmatically via errors.As, and to unwrap to its underlying cause via
// errors.Is / errors.Unwrap so callers can still test against, e.g.,
// context.DeadlineExceeded or net.Error when they need to.
type RemoteError struct {
	// Code is the stable, comparable classification of this failure.
	Code ErrorCode
	// Phase is derived from Code and included for convenient, direct
	// access without a switch statement.
	Phase Phase
	// Message is a short, human-readable description. It is stable per
	// Code unless explicitly overridden by the constructing call site.
	Message string
	// Target identifies which remote endpoint this error came from, in
	// "host:port" form. It is empty for errors not tied to a specific
	// target (e.g. configuration validation errors).
	Target string
	// Retryable reports whether the retry engine should consider this
	// error safe to retry. It is set by classification, not by the
	// retry engine itself, so any caller doing manual retry logic gets
	// the same answer the built-in engine would.
	Retryable bool
	// Detail carries additional free-form diagnostic context, such as a
	// recovered panic's stack trace, or a protocol-level status code
	// string. It is never required for programmatic handling.
	Detail string
	// Cause is the underlying error, if any (a *net.OpError, a
	// context error, an x/crypto/ssh error, etc.). Unwrap returns this.
	Cause error
}

// Error implements the error interface.
func (e *RemoteError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = humanMessage(e.Code)
	}
	var b []byte
	b = append(b, "remotego: "...)
	b = append(b, e.Phase.String()...)
	b = append(b, '/')
	b = append(b, e.Code.String()...)
	if e.Target != "" {
		b = append(b, ' ', '[')
		b = append(b, e.Target...)
		b = append(b, ']')
	}
	b = append(b, ':', ' ')
	b = append(b, msg...)
	if e.Detail != "" {
		b = append(b, " ("...)
		b = append(b, e.Detail...)
		b = append(b, ')')
	}
	if e.Cause != nil {
		b = append(b, ": "...)
		b = append(b, e.Cause.Error()...)
	}
	return string(b)
}

// Unwrap exposes the underlying cause for errors.Is/errors.As chains.
func (e *RemoteError) Unwrap() error {
	return e.Cause
}

// Is allows errors.Is(err, target) to match on ErrorCode equality when the
// target is itself a *RemoteError, in addition to the normal cause chain
// comparison. This lets callers write:
//
//	errors.Is(err, &remotego.RemoteError{Code: remotego.ErrCodeTimeout})
//
// as a convenient (if slightly unusual) alternative to the errors.As +
// switch-on-Code pattern used elsewhere in this package.
func (e *RemoteError) Is(target error) bool {
	other, ok := target.(*RemoteError)
	if !ok {
		return false
	}
	if other.Code == ErrCodeUnknown {
		return false
	}
	return e.Code == other.Code
}

// NewError constructs a *RemoteError for code, attaching target and cause.
// Phase and the default Message are derived automatically from code.
func NewError(code ErrorCode, target string, cause error) *RemoteError {
	return &RemoteError{
		Code:      code,
		Phase:     phaseForCode(code),
		Message:   humanMessage(code),
		Target:    target,
		Retryable: DefaultRetryable(code),
		Cause:     cause,
	}
}

// NewErrorf is like NewError but overrides Message with a formatted string.
func NewErrorf(code ErrorCode, target string, cause error, format string, args ...any) *RemoteError {
	e := NewError(code, target, cause)
	e.Message = fmt.Sprintf(format, args...)
	return e
}

// WithDetail returns a shallow copy of e with Detail set, for fluent
// construction at call sites (e.g. attaching a stack trace or a raw
// protocol status line without losing the original classification).
func (e *RemoteError) WithDetail(detail string) *RemoteError {
	clone := *e
	clone.Detail = detail
	return &clone
}

// DefaultRetryable reports the library's default retry policy for a given
// ErrorCode, independent of any specific error instance. The retry engine
// consults this (via the Retryable field it copies onto each RemoteError)
// unless the developer overrides classification with RetryPolicy.Classify.
//
// The policy embodies the "anti-lockout" guarantee: any error that implies
// the remote party has evaluated and rejected an identity is never
// retryable by default, because retrying it is indistinguishable from a
// brute-force attempt and risks tripping account lockout policies.
func DefaultRetryable(code ErrorCode) bool {
	switch code {
	case ErrCodeInvalidCredentials,
		ErrCodeKeyRejected,
		ErrCodeAccountLocked,
		ErrCodeMFAChallengeRequired,
		ErrCodeUnsupportedAuthMethod,
		ErrCodeProtocolMismatch,
		ErrCodeContextCanceled,
		ErrCodeClientClosed,
		ErrCodeInvalidTarget,
		ErrCodeCommandFailed:
		return false
	case ErrCodeTimeout,
		ErrCodeHostUnreachable,
		ErrCodeConnectionRefused,
		ErrCodeDNSResolutionFailed,
		ErrCodeSocketExhaustion,
		ErrCodeConnectionReset,
		ErrCodeNetworkUnreachable,
		ErrCodeHandshakeCorrupted,
		ErrCodeTLSFailure,
		ErrCodeAuthTimeout,
		ErrCodePanicRecovered:
		return true
	default:
		return false
	}
}

// --- Programmatic classification helpers -----------------------------------

// AsRemoteError extracts a *RemoteError from err via errors.As. It is a thin
// convenience wrapper so call sites don't need to declare the target
// variable inline every time.
func AsRemoteError(err error) (*RemoteError, bool) {
	var re *RemoteError
	if errors.As(err, &re) {
		return re, true
	}
	return nil, false
}

// CodeOf returns the ErrorCode of err if it is (or wraps) a *RemoteError,
// and ErrCodeUnknown otherwise.
func CodeOf(err error) ErrorCode {
	if re, ok := AsRemoteError(err); ok {
		return re.Code
	}
	return ErrCodeUnknown
}

// PhaseOf returns the Phase of err if it is (or wraps) a *RemoteError, and
// PhaseUnknown otherwise.
func PhaseOf(err error) Phase {
	if re, ok := AsRemoteError(err); ok {
		return re.Phase
	}
	return PhaseUnknown
}

// IsAuthFailed reports whether err represents any authentication-phase
// failure (invalid credentials, key rejection, account lock, or MFA
// challenge). This is the single check most callers want when they simply
// need to know "was this a bad password, in the broad sense".
func IsAuthFailed(err error) bool {
	re, ok := AsRemoteError(err)
	if !ok {
		return false
	}
	switch re.Code {
	case ErrCodeInvalidCredentials, ErrCodeKeyRejected, ErrCodeAccountLocked, ErrCodeMFAChallengeRequired:
		return true
	default:
		return false
	}
}

// IsInvalidCredentials reports whether err specifically means the
// username/password or username/key pair was rejected as wrong (as opposed
// to being locked out or facing an MFA challenge).
func IsInvalidCredentials(err error) bool {
	return CodeOf(err) == ErrCodeInvalidCredentials || CodeOf(err) == ErrCodeKeyRejected
}

// IsAccountLocked reports whether err means the target reported the
// account as locked or administratively disabled.
func IsAccountLocked(err error) bool {
	return CodeOf(err) == ErrCodeAccountLocked
}

// IsMFAChallengeRequired reports whether err means the target demanded an
// additional authentication factor the library could not satisfy.
func IsMFAChallengeRequired(err error) bool {
	return CodeOf(err) == ErrCodeMFAChallengeRequired
}

// IsNetworkTransient reports whether err represents a network-layer
// failure that is generally safe to retry (timeouts, resets, refused
// connections, socket exhaustion) as distinct from a definitive protocol
// or auth rejection. This is the primary signal the retry engine's default
// classification is built on, exported so callers doing their own retry
// loops (e.g. around DispatchBatch results) can reuse it.
func IsNetworkTransient(err error) bool {
	re, ok := AsRemoteError(err)
	if !ok {
		// Fall back to inspecting raw net errors for callers that pass
		// non-RemoteError values (e.g. errors from their own code paths).
		var netErr net.Error
		if errors.As(err, &netErr) {
			return netErr.Timeout() || isResetOrRefused(err)
		}
		return false
	}
	if re.Phase != PhaseNetwork {
		return false
	}
	return true
}

// IsRetryable reports whether the retry engine's default policy would
// retry err. It is exported so callers building custom retry loops around
// DispatchBatch results can apply the same anti-lockout-aware policy
// without duplicating the switch statement.
func IsRetryable(err error) bool {
	if re, ok := AsRemoteError(err); ok {
		return re.Retryable
	}
	// Unclassified errors are treated conservatively: retry network-shaped
	// failures, refuse everything else.
	return IsNetworkTransient(err)
}

// IsSocketExhaustion reports whether err represents local or remote OS
// socket/file-descriptor exhaustion (EMFILE, ENFILE, or the Windows
// WSAENOBUFS/WSAEMFILE equivalents surfaced through the Go runtime).
func IsSocketExhaustion(err error) bool {
	return CodeOf(err) == ErrCodeSocketExhaustion
}

func isResetOrRefused(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED)
}

// ClassifyNetError inspects a raw error returned from a net.Dial /
// net.Conn I/O call (or a context error) and produces the appropriately
// classified *RemoteError. It is the canonical entry point used by every
// dialer in this library so that classification logic lives in exactly one
// place; protocol-specific code should call this before falling back to
// its own protocol-level classification.
func ClassifyNetError(target string, err error) *RemoteError {
	if err == nil {
		return nil
	}

	// Context cancellation takes priority: it tells the caller the failure
	// was their own choice to stop waiting, not a target-side problem.
	if errors.Is(err, context.DeadlineExceeded) {
		return NewError(ErrCodeTimeout, target, err)
	}
	if errors.Is(err, context.Canceled) {
		return NewError(ErrCodeContextCanceled, target, err)
	}

	// OS-level resource exhaustion must be detected before generic
	// timeout/refused handling, since EMFILE/ENFILE often also satisfy
	// net.Error's Temporary()-shaped checks on some platforms.
	if isSocketExhaustionErr(err) {
		return NewError(ErrCodeSocketExhaustion, target, err)
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return NewError(ErrCodeConnectionRefused, target, err)
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return NewError(ErrCodeConnectionReset, target, err)
	}
	if errors.Is(err, syscall.EHOSTUNREACH) {
		return NewError(ErrCodeHostUnreachable, target, err)
	}
	if errors.Is(err, syscall.ENETUNREACH) {
		return NewError(ErrCodeNetworkUnreachable, target, err)
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return NewError(ErrCodeDNSResolutionFailed, target, err)
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return NewError(ErrCodeTimeout, target, err)
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return NewError(ErrCodeTimeout, target, err)
		}
		// Fall back to string inspection for platform-specific wrapped
		// syscall errors that don't satisfy errors.Is cleanly (notably
		// some Windows WSA* codes surfaced through os.SyscallError).
		if isRefusedString(opErr) {
			return NewError(ErrCodeConnectionRefused, target, err)
		}
		return NewError(ErrCodeHostUnreachable, target, err)
	}

	// Unrecognized shape: still classify as a network failure rather than
	// leaking an untyped error, but keep it conservatively retryable=false
	// by routing through timeout's sibling classification would be wrong;
	// default to host-unreachable since that's the safest "something is
	// wrong reaching this target" bucket while remaining retryable.
	return NewError(ErrCodeHostUnreachable, target, err)
}

// isSocketExhaustionErr reports whether err (directly or wrapped) is one of
// the OS-level "out of socket/file-descriptor resources" errors: EMFILE
// (per-process fd limit), ENFILE (system-wide fd table full), or ENOBUFS
// (kernel network buffer exhaustion — the WSAENOBUFS equivalent on the
// syscall package's cross-platform constants).
func isSocketExhaustionErr(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) {
		return true
	}
	// ENOBUFS is defined on all Go-supported platforms (mapped from
	// WSAENOBUFS on Windows) and is the kernel's signal that it could not
	// allocate a buffer for a new socket/connection.
	if errors.Is(err, syscall.ENOBUFS) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS:
			return true
		}
	}
	var pathErr *os.SyscallError
	if errors.As(err, &pathErr) {
		return isSocketExhaustionErr(pathErr.Err)
	}
	return false
}

// isRefusedString is a last-resort classifier for platforms/stdlib
// versions where "connection refused" doesn't unwrap cleanly to
// syscall.ECONNREFUSED (observed historically on some Windows builds).
func isRefusedString(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

// panicToError converts a recovered panic value into a *RemoteError with
// ErrCodePanicRecovered, preserving the panic value's string form and a
// caller-supplied stack trace in Detail. It never itself panics, regardless
// of what was recovered (including nil, error, string, or arbitrary types).
func panicToError(target string, recovered any, stack string) *RemoteError {
	var msg string
	switch v := recovered.(type) {
	case error:
		msg = v.Error()
	case string:
		msg = v
	default:
		msg = fmt.Sprintf("%v", v)
	}
	e := NewErrorf(ErrCodePanicRecovered, target, nil, "recovered panic: %s", msg)
	e.Detail = stack
	return e
}
