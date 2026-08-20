package sources

import (
	"context"
	"net/http"
	"time"
)

// Result holds output from one enumeration source.
type Result struct {
	Name     string
	Domains  []string
	Duration time.Duration
	Attempts int
	Err      error
	Skipped  bool // true when the binary/tool is not installed
}

// Source is implemented by every enumeration backend.
type Source interface {
	Name() string
	Enumerate(ctx context.Context, domain string, client *http.Client) Result
}

// dedup returns unique, non-empty strings preserving insertion order.
func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// retry runs fn up to maxAttempts times with delay between attempts.
// Returns as soon as fn succeeds (non-empty slice + nil error).
func retry(maxAttempts int, delay time.Duration, fn func() ([]string, error)) ([]string, int, error) {
	var (
		lastErr error
		result  []string
	)
	for i := 0; i < maxAttempts; i++ {
		r, err := fn()
		if err == nil && len(r) > 0 {
			return r, i + 1, nil
		}
		lastErr = err
		if i < maxAttempts-1 {
			time.Sleep(delay)
		}
	}
	return result, maxAttempts, lastErr
}
