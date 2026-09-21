// Package engine contains the protocol-agnostic concurrency and retry
// machinery behind remotego. It has no dependency on the public package —
// error classification is injected by the caller via the Classifier
// function type — so it can be unit-tested in isolation and reused by any
// future protocol dialer without import cycles.
package engine

import (
	"context"
	"math"
	"math/rand/v2"
	"time"
)

// RetryPolicy configures the retry engine's exponential-backoff-with-
// jitter schedule and its anti-lockout safety behavior.
type RetryPolicy struct {
	// MaxRetries is the number of additional attempts after the first
	// one. Zero disables retrying (the operation runs exactly once).
	MaxRetries int
	// BaseDelay is the delay before the first retry. It must be > 0 for
	// retries to have any effect; a zero value is treated as 1ms.
	BaseDelay time.Duration
	// MaxDelay caps the computed backoff delay regardless of attempt
	// count. Zero means uncapped (only bounded by float64 range).
	MaxDelay time.Duration
	// Jitter is the fraction (0.0–1.0) of the computed delay that is
	// randomized in both directions, to avoid synchronized retry storms
	// across a large batch of targets failing at the same time.
	Jitter float64
	// OverrideNonRetryable, when true, retries errors the Classifier
	// marked non-retryable (e.g. credential rejections). Default false:
	// this is what implements the anti-brute-force-lockout guarantee.
	OverrideNonRetryable bool

	// rand is the jitter source. Nil means use the package default
	// (math/rand/v2, safe for concurrent use). Tests override this for
	// determinism.
	rand func() float64
}

// randFn returns the policy's jitter source, defaulting to a
// concurrency-safe global source when unset.
func (p RetryPolicy) randFn() func() float64 {
	if p.rand != nil {
		return p.rand
	}
	return rand.Float64
}

// Classification is the minimal information the retry engine needs about
// an error to decide whether to retry it. Protocol dialers and the public
// package translate their rich error types into this shape via a
// Classifier so that internal/engine never imports remotego.
type Classification struct {
	// Retryable reports whether this error is, in principle, safe to
	// retry (a transient network failure) as opposed to a definitive
	// rejection (bad credentials, protocol mismatch).
	Retryable bool
	// Fatal marks errors that must never be retried, even when the policy
	// sets OverrideNonRetryable (e.g. caller cancellation, invalid input).
	Fatal bool
}

// Classifier extracts a Classification from an error returned by the
// operation being retried. It is called with the raw error from Operation
// and must handle nil defensively (though Do never calls it with nil).
type Classifier func(err error) Classification

// Operation is the function retried by Do. It must itself respect ctx
// cancellation for any blocking work it performs.
type Operation func(ctx context.Context, attempt int) error

// Do runs op, retrying according to policy until it succeeds, ctx is
// canceled, retries are exhausted, or classify reports the most recent
// error as non-retryable (and OverrideNonRetryable is false).
//
// attempt is 0-indexed and passed to op so operations can vary behavior
// (e.g. logging) by attempt number. Do returns the error from the final
// attempt, unwrapped from any retry-loop bookkeeping — callers see exactly
// what the last call to op returned.
func Do(ctx context.Context, policy RetryPolicy, classify Classifier, op Operation) error {
	if classify == nil {
		classify = func(error) Classification { return Classification{Retryable: false} }
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}

		lastErr = op(ctx, attempt)
		if lastErr == nil {
			return nil
		}

		if attempt >= policy.MaxRetries {
			return lastErr
		}

		c := classify(lastErr)
		if c.Fatal || (!c.Retryable && !policy.OverrideNonRetryable) {
			return lastErr
		}

		delay := BackoffWithJitter(attempt+1, policy.BaseDelay, policy.MaxDelay, policy.Jitter, policy.randFn())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return lastErr
		case <-timer.C:
		}
	}
}

// BackoffWithJitter computes the delay before retry attempt n (1-indexed:
// n=1 is the delay before the first retry), doubling base on each
// subsequent attempt up to max, then randomizing the result by ±jitter
// fraction. rnd must return a value in [0, 1); pass nil to use the
// package's default concurrency-safe source.
//
// It is exported so the public package's option validation and any tests
// can reason about the exact schedule without duplicating the math.
func BackoffWithJitter(n int, base, max time.Duration, jitter float64, rnd func() float64) time.Duration {
	if rnd == nil {
		rnd = rand.Float64
	}
	if base <= 0 {
		base = time.Millisecond
	}
	if n < 1 {
		n = 1
	}
	// Cap the exponent so math.Pow can't overflow into +Inf for large
	// attempt counts before the max-delay clamp gets a chance to apply.
	const maxExponent = 62
	exp := n - 1
	if exp > maxExponent {
		exp = maxExponent
	}

	d := float64(base) * math.Pow(2, float64(exp))
	if max > 0 && d > float64(max) {
		d = float64(max)
	}

	if jitter > 0 {
		if jitter > 1 {
			jitter = 1
		}
		delta := d * jitter
		// rnd() in [0,1) -> spread in [-delta, +delta)
		d = d - delta + (rnd() * 2 * delta)
	}
	if d < 0 {
		d = 0
	}
	if d >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return time.Duration(d)
}
