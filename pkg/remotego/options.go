package remotego

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// ClientOption configures a Client via the functional-options pattern.
// Options are applied in the order passed to NewClient, so a later option
// overrides an earlier one on conflicting fields.
type ClientOption func(*clientConfig)

// clientConfig holds every knob a Client's behavior depends on. It is
// unexported: developers only ever touch it through ClientOption values,
// which keeps this struct free to grow without breaking callers.
type clientConfig struct {
	EventCallback EventCallback
	// DialTimeout bounds establishing the raw TCP (and, where applicable,
	// TLS) connection. Zero means no explicit timeout beyond ctx.
	DialTimeout time.Duration
	// HandshakeTimeout bounds the protocol handshake/banner exchange that
	// happens after the TCP connection is up but before auth starts.
	HandshakeTimeout time.Duration
	// AuthTimeout bounds the authentication exchange itself.
	AuthTimeout time.Duration

	// Retries is the number of additional attempts after the first one,
	// per target, for Probe/Dial calls made through DispatchBatch (or
	// manually wrapped by the caller). Zero disables retrying. Default: 0.
	Retries int
	// RetryBaseDelay is the base delay for exponential backoff between
	// retries. Default: 250ms.
	RetryBaseDelay time.Duration
	// RetryMaxDelay caps the backoff delay regardless of attempt count.
	// Default: 10s.
	RetryMaxDelay time.Duration
	// RetryJitter is the fraction (0.0–1.0) of the computed backoff delay
	// that is randomized, to avoid thundering-herd retries against the
	// same fleet of targets. Default: 0.2 (±20%).
	RetryJitter float64
	// RetryOverrideNonRetryable, when true, allows the retry engine to
	// retry error classes that are non-retryable by default (e.g.
	// InvalidCredentials, AccountLocked). This is OFF by default and
	// exists only as an explicit escape hatch: turning it on disables the
	// anti-lockout guarantee, so the developer must opt in deliberately.
	RetryOverrideNonRetryable bool

	// MaxConcurrency bounds the number of in-flight dial/probe operations
	// a single DispatchBatch call will run at once. Zero (the default)
	// means unbounded: the dispatcher spawns one goroutine per target and
	// lets the Go runtime and OS scheduler absorb the load. This is a
	// deliberate design choice — the library never silently throttles a
	// developer's workload. Set it explicitly via WithMaxConcurrency to
	// bound resource usage on constrained hosts or against fragile targets.
	MaxConcurrency int

	// ResultBufferSize sets the buffer depth of the channel DispatchBatch
	// streams results through. Zero means unbuffered (each result blocks
	// the producing goroutine until the consumer reads it). A larger
	// buffer smooths out bursty producer/consumer speed mismatches at the
	// cost of memory. Default: 64.
	ResultBufferSize int

	// TCPKeepAlive sets the OS-level TCP keep-alive interval on dialed
	// connections. Zero disables keep-alive probes. Default: 30s.
	TCPKeepAlive time.Duration
	// NoDelay disables Nagle's algorithm (sets TCP_NODELAY) on dialed
	// connections. Default: true, since interactive SSH/RDP sessions
	// benefit from low per-write latency far more than from coalescing.
	NoDelay bool

	// InsecureSkipTLSVerify disables server certificate verification for
	// protocols that negotiate TLS (RDP's PROTOCOL_SSL path). Default:
	// false. Only intended for lab/test environments or first-contact
	// trust-on-first-use workflows the developer manages themselves.
	InsecureSkipTLSVerify bool

	// RatePerSecond, when > 0, limits how many operations DispatchBatch
	// *starts* per second. Zero (default) disables rate limiting.
	RatePerSecond float64
	// RateBurst is the token-bucket burst size for RatePerSecond.
	RateBurst int
	// AdaptiveRate, when true and RatePerSecond > 0, automatically slows
	// the start rate when local socket exhaustion is observed and
	// gradually recovers afterwards.
	AdaptiveRate bool

	// HostKeyCallback verifies SSH server host keys. Nil means host keys
	// are NOT verified (see WithHostKeyCallback).
	HostKeyCallback ssh.HostKeyCallback
}

// defaultConfig returns a clientConfig populated with the library's
// defaults, before any ClientOption is applied.
func defaultConfig() *clientConfig {
	return &clientConfig{
		DialTimeout:      10 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		AuthTimeout:      15 * time.Second,

		Retries:        0,
		RetryBaseDelay: 250 * time.Millisecond,
		RetryMaxDelay:  10 * time.Second,
		RetryJitter:    0.2,

		MaxConcurrency:   0, // unbounded by default — see field doc above.
		ResultBufferSize: 64,

		TCPKeepAlive: 30 * time.Second,
		NoDelay:      true,

		InsecureSkipTLSVerify: false,
	}
}

// WithDialTimeout sets the timeout for establishing the raw connection.
func WithDialTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.DialTimeout = d }
}

// WithHandshakeTimeout sets the timeout for the protocol handshake phase.
func WithHandshakeTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.HandshakeTimeout = d }
}

// WithAuthTimeout sets the timeout for the authentication exchange.
func WithAuthTimeout(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.AuthTimeout = d }
}

// WithRetries sets the number of additional attempts after the first,
// applied per target by the built-in retry engine.
func WithRetries(n int) ClientOption {
	return func(c *clientConfig) {
		if n < 0 {
			n = 0
		}
		c.Retries = n
	}
}

// WithExponentialBackoff sets the base and max delay for the retry
// engine's exponential-backoff-with-jitter schedule. base is the delay
// before the first retry; it doubles on each subsequent attempt up to max.
func WithExponentialBackoff(base, max time.Duration) ClientOption {
	return func(c *clientConfig) {
		c.RetryBaseDelay = base
		c.RetryMaxDelay = max
	}
}

// WithRetryJitter sets the randomization fraction applied to each computed
// backoff delay. frac is clamped to [0, 1].
func WithRetryJitter(frac float64) ClientOption {
	return func(c *clientConfig) {
		if frac < 0 {
			frac = 0
		}
		if frac > 1 {
			frac = 1
		}
		c.RetryJitter = frac
	}
}

// WithRetryOverrideNonRetryable allows the retry engine to retry error
// classes that are non-retryable by default, such as InvalidCredentials or
// AccountLocked. This disables the library's anti-brute-force-lockout
// guarantee and should only be enabled with a clear understanding of the
// lockout risk against the target environment.
func WithRetryOverrideNonRetryable(allow bool) ClientOption {
	return func(c *clientConfig) { c.RetryOverrideNonRetryable = allow }
}

// WithMaxConcurrency bounds the number of concurrent dial/probe operations
// a single DispatchBatch call runs. Pass 0 (the default if this option is
// never used) to run fully unbounded — one goroutine per target, limited
// only by what the host OS and Go runtime can sustain.
func WithMaxConcurrency(n int) ClientOption {
	return func(c *clientConfig) {
		if n < 0 {
			n = 0
		}
		c.MaxConcurrency = n
	}
}

// WithResultBufferSize sets the buffer depth of the channel DispatchBatch
// streams results through.
func WithResultBufferSize(n int) ClientOption {
	return func(c *clientConfig) {
		if n < 0 {
			n = 0
		}
		c.ResultBufferSize = n
	}
}

// WithTCPKeepAlive sets the OS-level TCP keep-alive interval on dialed
// connections. Pass 0 to disable keep-alive probes entirely.
func WithTCPKeepAlive(d time.Duration) ClientOption {
	return func(c *clientConfig) { c.TCPKeepAlive = d }
}

// WithNoDelay controls whether TCP_NODELAY is set on dialed connections.
func WithNoDelay(enabled bool) ClientOption {
	return func(c *clientConfig) { c.NoDelay = enabled }
}

// WithInsecureSkipTLSVerify disables server certificate verification for
// protocols that negotiate TLS. Intended for controlled lab/test use.
func WithInsecureSkipTLSVerify(skip bool) ClientOption {
	return func(c *clientConfig) { c.InsecureSkipTLSVerify = skip }
}

// WithRateLimit limits how many operations DispatchBatch starts per second,
// with the given burst. perSecond <= 0 disables rate limiting (default).
func WithRateLimit(perSecond float64, burst int) ClientOption {
	return func(c *clientConfig) {
		c.RatePerSecond = perSecond
		c.RateBurst = burst
	}
}

// WithAdaptiveRateLimit enables automatic slow-down of the start rate when
// the local host reports socket exhaustion. It has no effect unless a rate
// limit is set with WithRateLimit.
func WithAdaptiveRateLimit(enabled bool) ClientOption {
	return func(c *clientConfig) { c.AdaptiveRate = enabled }
}

// WithHostKeyCallback sets the SSH host key verification callback (see
// golang.org/x/crypto/ssh/knownhosts). If never set, host keys are NOT
// verified, which suits reachability/credential probing of large fleets but
// exposes Dial sessions to man-in-the-middle attacks. Production code that
// sends secrets over Dial sessions should always set this.
func WithHostKeyCallback(cb ssh.HostKeyCallback) ClientOption {
	return func(c *clientConfig) { c.HostKeyCallback = cb }
}

// WithEventCallback ثبت یک شنونده برای دریافت رویدادهای لحظه‌ای مانیتورینگ
func WithEventCallback(cb EventCallback) ClientOption {
	return func(c *clientConfig) {
		c.EventCallback = cb
	}
}
