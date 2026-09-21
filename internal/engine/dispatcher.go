package engine

import (
	"context"
	"fmt"
	"math"
	"runtime"
	"sync"
	"time"
)

// Result is one element of a dispatch stream: the outcome for the input at
// position Index in the slice passed to Dispatch. Exactly len(inputs)
// Results are always emitted, in completion order (not input order).
type Result[O any] struct {
	Index int
	Value O
	Err   error
}

// Config configures a Dispatcher.
type Config struct {
	// MaxConcurrency bounds in-flight operations. Zero (default) means
	// unbounded: one goroutine per input, no semaphore, no clamping.
	MaxConcurrency int
	// ResultBuffer is the capacity of the result channel.
	ResultBuffer int
	// RatePerSecond, when > 0, enables a token-bucket limiter on task
	// *starts*. Zero disables rate limiting entirely.
	RatePerSecond float64
	// RateBurst is the bucket size for the limiter (min 1).
	RateBurst int
	// Adaptive, when true and rate limiting is enabled, halves the
	// current rate whenever IsBackpressure reports an error and slowly
	// recovers toward RatePerSecond on successes.
	Adaptive bool
	// IsBackpressure classifies errors that indicate local resource
	// pressure (e.g. socket exhaustion). Used only when Adaptive is set.
	IsBackpressure func(error) bool
	// OnPanic converts a recovered panic value and its stack trace into
	// an error. If nil, a generic error is produced.
	OnPanic func(recovered any, stack []byte) error
	// WrapCtxErr converts a context error into the error reported for
	// inputs that were never started because ctx ended. If nil, the raw
	// context error is used.
	WrapCtxErr func(index int, err error) error
}

// Dispatcher runs batches of operations concurrently. It is safe for
// concurrent use; each Dispatch call is independent, but they share the
// same rate limiter if one is configured.
type Dispatcher struct {
	cfg     Config
	limiter *Limiter
}

// New returns a Dispatcher for cfg.
func New(cfg Config) *Dispatcher {
	if cfg.MaxConcurrency < 0 {
		cfg.MaxConcurrency = 0
	}
	if cfg.ResultBuffer < 0 {
		cfg.ResultBuffer = 0
	}
	d := &Dispatcher{cfg: cfg}
	d.limiter = NewLimiter(cfg.RatePerSecond, cfg.RateBurst)
	return d
}

// SetRate dynamically changes the rate limit at runtime. A rate <= 0
// disables limiting. It takes effect for subsequent task starts, including
// those of Dispatch calls already in progress.
func (d *Dispatcher) SetRate(perSecond float64, burst int) {
	d.limiter.SetRate(perSecond, burst)
}

// Rate reports the limiter's current rate (0 if disabled).
func (d *Dispatcher) Rate() float64 {
	return d.limiter.Rate()
}

// stackPool recycles the buffers used to capture panic stack traces.
var stackPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16<<10)
		return &b
	},
}

// captureStack returns a copy of the current goroutine's stack, using a
// pooled scratch buffer to avoid a large allocation per recovered panic.
func captureStack() []byte {
	bp := stackPool.Get().(*[]byte)
	n := runtime.Stack(*bp, false)
	out := make([]byte, n)
	copy(out, (*bp)[:n])
	stackPool.Put(bp)
	return out
}

func (d *Dispatcher) panicErr(r any) (err error) {
	// The conversion hook itself must never be able to crash the host.
	defer func() {
		if r2 := recover(); r2 != nil {
			err = fmt.Errorf("engine: panic while handling panic: %v (original: %v)", r2, r)
		}
	}()
	stack := captureStack()
	if d.cfg.OnPanic != nil {
		return d.cfg.OnPanic(r, stack)
	}
	return fmt.Errorf("engine: recovered panic: %v\n%s", r, stack)
}

// Dispatch runs fn for every element of inputs and streams exactly
// len(inputs) Results on the returned channel, which is closed after the
// last one. The caller MUST drain the channel (or cancel ctx and then
// drain) — producers block on send.
//
// Every invocation of fn runs inside its own recover boundary; a panic
// becomes that input's Result.Err. Cancelling ctx stops new starts;
// unstarted inputs are reported with a context error.
func Dispatch[I, O any](ctx context.Context, d *Dispatcher, inputs []I, fn func(ctx context.Context, index int, in I) (O, error)) <-chan Result[O] {
	n := len(inputs)
	out := make(chan Result[O], d.cfg.ResultBuffer)

	go func() {
		defer close(out)

		var wg sync.WaitGroup
		var sem chan struct{}
		if d.cfg.MaxConcurrency > 0 {
			sem = make(chan struct{}, d.cfg.MaxConcurrency)
		}

		next := 0
		failRemaining := func(err error) {
			for ; next < n; next++ {
				e := err
				if d.cfg.WrapCtxErr != nil {
					e = d.cfg.WrapCtxErr(next, err)
				}
				out <- Result[O]{Index: next, Err: e}
			}
		}

		func() {
			// Isolation boundary for the launch loop itself.
			defer func() {
				if r := recover(); r != nil {
					failRemaining(d.panicErr(r))
				}
			}()

			for next < n {
				if err := ctx.Err(); err != nil {
					failRemaining(err)
					return
				}
				if err := d.limiter.Wait(ctx); err != nil {
					failRemaining(err)
					return
				}
				if sem != nil {
					select {
					case sem <- struct{}{}:
					case <-ctx.Done():
						failRemaining(ctx.Err())
						return
					}
				}

				i := next
				next++
				wg.Add(1)
				go runTask(ctx, d, &wg, sem, out, i, inputs[i], fn)
			}
		}()

		wg.Wait()
	}()

	return out
}

// runTask executes one task inside a recovery boundary and sends its result.
// It is a free function because methods cannot declare type parameters.
func runTask[I, O any](ctx context.Context, d *Dispatcher, wg *sync.WaitGroup, sem chan struct{}, out chan<- Result[O], index int, in I, fn func(context.Context, int, I) (O, error)) {
	defer wg.Done()
	if sem != nil {
		defer func() { <-sem }()
	}

	var res Result[O]
	res.Index = index
	func() {
		defer func() {
			if r := recover(); r != nil {
				var zero O
				res.Value = zero
				res.Err = d.panicErr(r)
			}
		}()
		res.Value, res.Err = fn(ctx, index, in)
	}()

	if d.cfg.Adaptive {
		if res.Err != nil && d.cfg.IsBackpressure != nil && d.cfg.IsBackpressure(res.Err) {
			d.limiter.Throttle()
		} else if res.Err == nil {
			d.limiter.Recover()
		}
	}

	out <- res
}

// Limiter is a token-bucket rate limiter whose rate can be changed while
// in use. A rate <= 0 means unlimited.
type Limiter struct {
	mu      sync.Mutex
	ceiling float64 // configured rate; adaptive recovery never exceeds it
	rate    float64
	burst   float64
	tokens  float64
	last    time.Time
}

// NewLimiter returns a Limiter allowing rate events per second with the
// given burst (minimum 1).
func NewLimiter(rate float64, burst int) *Limiter {
	l := &Limiter{}
	l.SetRate(rate, burst)
	return l
}

// SetRate changes the rate and burst. It also resets the adaptive ceiling.
func (l *Limiter) SetRate(rate float64, burst int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if burst < 1 {
		burst = 1
	}
	l.refill(time.Now())
	l.ceiling = rate
	l.rate = rate
	l.burst = float64(burst)
	l.tokens = math.Min(l.tokens, l.burst)
	if l.last.IsZero() {
		l.tokens = l.burst
		l.last = time.Now()
	}
}

// Rate returns the current (possibly adaptively reduced) rate.
func (l *Limiter) Rate() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rate
}

// Throttle halves the current rate (floor: 1/60 per second) in response to
// backpressure.
func (l *Limiter) Throttle() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return
	}
	l.rate = math.Max(l.rate/2, 1.0/60)
}

// Recover nudges the rate back up 5% toward the configured ceiling.
func (l *Limiter) Recover() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 || l.rate >= l.ceiling {
		return
	}
	l.rate = math.Min(l.rate*1.05, l.ceiling)
}

// refill adds tokens for elapsed time. l.mu must be held.
func (l *Limiter) refill(now time.Time) {
	if l.last.IsZero() {
		return
	}
	if l.rate > 0 {
		l.tokens = math.Min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
}

// Wait blocks until a token is available or ctx ends.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		if l.rate <= 0 {
			l.mu.Unlock()
			return ctx.Err()
		}
		l.refill(time.Now())
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.rate * float64(time.Second))
		l.mu.Unlock()

		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}
