package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Subfinder wraps the external subfinder binary.
type Subfinder struct{}

func (s *Subfinder) Name() string { return "subfinder" }

func (s *Subfinder) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()

	if _, err := exec.LookPath("subfinder"); err != nil {
		return Result{Name: s.Name(), Skipped: true, Duration: time.Since(start),
			Err: errors.New("subfinder not in PATH")}
	}

	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return runExternalTool(ctx, "subfinder", "-d", domain, "-all", "-recursive", "-silent")
	})

	return Result{
		Name:     s.Name(),
		Domains:  dedup(filterBySuffix(domains, domain)),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

// Assetfinder wraps the external assetfinder binary.
type Assetfinder struct{}

func (a *Assetfinder) Name() string { return "assetfinder" }

func (a *Assetfinder) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()

	if _, err := exec.LookPath("assetfinder"); err != nil {
		return Result{Name: a.Name(), Skipped: true, Duration: time.Since(start),
			Err: errors.New("assetfinder not in PATH")}
	}

	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return runExternalTool(ctx, "assetfinder", "--subs-only", domain)
	})

	return Result{
		Name:     a.Name(),
		Domains:  dedup(filterBySuffix(domains, domain)),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

// Findomain wraps the external findomain binary.
type Findomain struct{}

func (f *Findomain) Name() string { return "findomain" }

func (f *Findomain) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()

	if _, err := exec.LookPath("findomain"); err != nil {
		return Result{Name: f.Name(), Skipped: true, Duration: time.Since(start),
			Err: errors.New("findomain not in PATH")}
	}

	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return runExternalTool(ctx, "findomain", "--quiet", "-t", domain, "--threads", "20")
	})

	return Result{
		Name:     f.Name(),
		Domains:  dedup(filterBySuffix(domains, domain)),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

// runExternalTool executes a binary and collects stdout lines.
func runExternalTool(ctx context.Context, name string, args ...string) ([]string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Exit code 1 is common in security tools (no results), not a real error
		if _, ok := err.(*exec.ExitError); ok && stdout.Len() > 0 {
			// still has output — treat as partial success
		} else if stdout.Len() == 0 {
			return nil, err
		}
	}

	var results []string
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		line := strings.TrimSpace(strings.ToLower(sc.Text()))
		if line != "" {
			results = append(results, line)
		}
	}
	return results, sc.Err()
}

// filterBySuffix keeps only domains that end with .domain or equal domain.
func filterBySuffix(domains []string, root string) []string {
	suffix := "." + root
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if strings.HasSuffix(d, suffix) || d == root {
			out = append(out, d)
		}
	}
	return out
}
