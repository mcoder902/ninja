package remotego

import (
	"context"
	"net"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/mcoder902/ninja/internal/engine"
)

type Client struct {
	cfg    *clientConfig
	dialer *net.Dialer
	disp   *engine.Dispatcher
	base   context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

func panicGuard(target string, errp *error) {
	if r := recover(); r != nil {
		*errp = panicToError(target, r, string(debug.Stack()))
	}
}

func (c *Client) begin(t Target, ctx context.Context) (context.Context, func(), error) {
	if c.closed.Load() {
		return ctx, func() {}, NewError(ErrCodeClientClosed, t.Addr(), nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.base, cancel)
	return ctx, func() { stop(); cancel() }, nil
}

func (c *Client) finish(t Target, err error) error {
	if err == nil {
		return nil
	}
	re, ok := AsRemoteError(err)
	if !ok {
		re = ClassifyNetError(t.Addr(), err)
	}
	if c.closed.Load() && re.Code == ErrCodeContextCanceled {
		return NewError(ErrCodeClientClosed, t.Addr(), err)
	}
	return re
}

func (c *Client) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.cancel()
	}
	return nil
}

func (c *Client) SetRateLimit(perSecond float64, burst int) {
	c.disp.SetRate(perSecond, burst)
}

func NewClient(opts ...ClientOption) *Client {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	base, cancel := context.WithCancel(context.Background())
	return &Client{
		cfg: cfg,
		dialer: &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: keepAliveOrDisabled(cfg.TCPKeepAlive),
		},
		disp: engine.New(engine.Config{
			MaxConcurrency: cfg.MaxConcurrency,
			ResultBuffer:   cfg.ResultBufferSize,
			RatePerSecond:  cfg.RatePerSecond,
			RateBurst:      cfg.RateBurst,
			Adaptive:       cfg.AdaptiveRate,
			IsBackpressure: IsSocketExhaustion,
			OnPanic: func(recovered any, stack []byte) error {
				return panicToError("", recovered, string(stack))
			},
		}),
		base:   base,
		cancel: cancel,
	}
}

func keepAliveOrDisabled(d time.Duration) time.Duration {
	if d <= 0 {
		return -1
	}
	return d
}

func (c *Client) dialTCP(ctx context.Context, t Target) (net.Conn, error) {
	addr := t.Addr()
	conn, err := c.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, ClassifyNetError(addr, err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(c.cfg.NoDelay)
	}
	return conn, nil
}

func (c *Client) Probe(ctx context.Context, t Target) (result ProbeResult) {
	result.Target = t
	start := time.Now()
	defer func() {
		result.Latency = time.Since(start)
	}()
	defer func() {
		if r := recover(); r != nil {
			result.Err = panicToError(t.Addr(), r, string(debug.Stack()))
		}
	}()

	if err := t.Validate(); err != nil {
		result.Err = NewErrorf(ErrCodeInvalidTarget, t.Addr(), err, "%s", err.Error())
		return result
	}

	ctx, end, berr := c.begin(t, ctx)
	defer end()
	if berr != nil {
		result.Err = berr
		return result
	}

	policy := c.retryPolicy()
	attempts := 0
	runErr := engine.Do(ctx, policy, remoteClassifier, func(ctx context.Context, attempt int) error {
		attempts = attempt + 1
		switch t.Protocol {
		case ProtocolSSH:
			return c.probeSSH(ctx, t, &result)
		case ProtocolRDP:
			return c.probeRDP(ctx, t, &result)
		default:
			return NewError(ErrCodeInvalidTarget, t.Addr(), nil)
		}
	})

	result.Attempts = attempts
	result.Err = c.finish(t, runErr)
	return result
}

func (c *Client) probeSSH(ctx context.Context, t Target, result *ProbeResult) error {
	out := c.sshConnect(ctx, t)
	result.Reachable = out.reachable
	result.ProtocolConfirmed = out.confirmed
	result.Banner = out.banner
	result.ServerVersion = parseSSHServerVersion(out.banner)
	if out.client != nil {
		result.AuthOK = out.authOK
		_ = out.client.Close()
	}
	return out.err
}

func (c *Client) probeRDP(ctx context.Context, t Target, result *ProbeResult) error {
	out := c.rdpConnect(ctx, t, true)
	result.Reachable = out.reachable
	result.ProtocolConfirmed = out.confirmed
	result.Banner = out.banner
	result.AuthOK = out.authOK

	if out.neg != nil && out.neg.Conn != nil {
		_ = out.neg.Conn.Close()
	}
	return out.err
}

func parseSSHServerVersion(banner string) string {
	if len(banner) > len("SSH-2.0-") && banner[:8] == "SSH-2.0-" {
		return banner[8:]
	}
	return ""
}

func (c *Client) Dial(ctx context.Context, t Target) (session Session, retErr error) {
	defer func() {
		if r := recover(); r != nil {
			if session != nil {
				_ = session.Close()
			}
			session, retErr = nil, panicToError(t.Addr(), r, string(debug.Stack()))
		}
	}()

	if err := t.Validate(); err != nil {
		return nil, NewErrorf(ErrCodeInvalidTarget, t.Addr(), err, "%s", err.Error())
	}

	ctx, end, berr := c.begin(t, ctx)
	defer end()
	if berr != nil {
		return nil, berr
	}

	policy := c.retryPolicy()
	err := engine.Do(ctx, policy, remoteClassifier, func(ctx context.Context, attempt int) error {
		switch t.Protocol {
		case ProtocolSSH:
			out := c.sshConnect(ctx, t)
			if out.err != nil {
				return out.err
			}
			sess := &SSHSession{target: t, client: out.client, serverVersion: out.banner}
			sess.state.Store(uint32(SessionStateActive))
			session = sess
			return nil

		case ProtocolRDP:
			out := c.rdpConnect(ctx, t, false)
			if out.err != nil {
				return out.err
			}
			sess := &RDPSession{
				target:   t,
				conn:     out.neg.Conn,
				selected: out.neg.Selected,
				certSubj: out.neg.PeerCertSubject,
			}
			sess.state.Store(uint32(SessionStateActive))
			session = sess
			return nil

		default:
			return NewError(ErrCodeInvalidTarget, t.Addr(), nil)
		}
	})

	if err != nil {
		return nil, c.finish(t, err)
	}
	return session, nil
}

type BatchResult struct {
	Target Target
	Probe  ProbeResult
}

func (c *Client) DispatchBatch(ctx context.Context, targets []Target) <-chan BatchResult {
	raw := engine.Dispatch(ctx, c.disp, targets, func(ctx context.Context, _ int, t Target) (ProbeResult, error) {
		return c.Probe(ctx, t), nil
	})

	out := make(chan BatchResult, c.cfg.ResultBufferSize)
	go func() {
		defer close(out)
		for r := range raw {
			if r.Err != nil {
				t := targets[r.Index]
				out <- BatchResult{Target: t, Probe: ProbeResult{Target: t, Err: c.finish(t, r.Err)}}
				continue
			}
			out <- BatchResult{Target: targets[r.Index], Probe: r.Value}
		}
	}()
	return out
}

func (c *Client) retryPolicy() engine.RetryPolicy {
	return engine.RetryPolicy{
		MaxRetries:           c.cfg.Retries,
		BaseDelay:            c.cfg.RetryBaseDelay,
		MaxDelay:             c.cfg.RetryMaxDelay,
		Jitter:               c.cfg.RetryJitter,
		OverrideNonRetryable: c.cfg.RetryOverrideNonRetryable,
	}
}

func remoteClassifier(err error) engine.Classification {
	if re, ok := AsRemoteError(err); ok {
		switch re.Code {
		case ErrCodeContextCanceled, ErrCodeClientClosed, ErrCodeInvalidTarget:
			return engine.Classification{Fatal: true}
		default:
			return engine.Classification{Retryable: re.Retryable}
		}
	}
	return engine.Classification{Retryable: IsNetworkTransient(err)}
}

func (c *Client) emitEvent(t Target, et EventType, detail string) {
	if c != nil && c.cfg != nil && c.cfg.EventCallback != nil {
		c.cfg.EventCallback(ProbeEvent{
			Target:    t,
			Type:      et,
			Timestamp: time.Now(),
			Detail:    detail,
		})
	}
}
