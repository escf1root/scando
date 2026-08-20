package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/escf1root/scando/internal/sources"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// Config controls runner behaviour.
type Config struct {
	Timeout     time.Duration // per-source timeout
	MaxParallel int           // max concurrent goroutines
	Silent      bool          // suppress status output (only domains to stdout)
}

// DefaultConfig returns production defaults matching original scando.sh.
func DefaultConfig() Config {
	return Config{
		Timeout:     60 * time.Second,
		MaxParallel: 8,
	}
}

// Runner orchestrates all enumeration sources in parallel.
type Runner struct {
	cfg     Config
	client  *http.Client
	sources []sources.Source
}

// New creates a Runner with all sources registered.
func New(cfg Config) *Runner {
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	client := &http.Client{
		Timeout:   cfg.Timeout + 5*time.Second,
		Transport: transport,
	}

	srcs := []sources.Source{
		// Passive OSINT APIs — no external binary required
		&sources.CrtSh{},
		&sources.OTX{},
		&sources.URLScan{},
		&sources.WebArchive{},
		&sources.HackerTarget{},
		&sources.ThreatMiner{},
		&sources.RapidDNS{},
		&sources.BufferOver{},
		&sources.Riddler{},
		// External tool wrappers — gracefully skipped when binary absent
		&sources.Subfinder{},
		&sources.Assetfinder{},
		&sources.Findomain{},
	}

	return &Runner{cfg: cfg, client: client, sources: srcs}
}

// Run executes all sources in parallel and returns the collected results.
func (r *Runner) Run(domain string) []*sources.Result {
	total := len(r.sources)
	results := make([]*sources.Result, total)
	var completed int64

	sem := make(chan struct{}, r.cfg.MaxParallel)
	var wg sync.WaitGroup

	if !r.cfg.Silent {
		r.logf("[i] Launching %d sources | parallel=%d | timeout=%s\n",
			total, r.cfg.MaxParallel, r.cfg.Timeout)
		r.printProgress(0, total)
	}

	for i, src := range r.sources {
		wg.Add(1)
		go func(idx int, s sources.Source) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), r.cfg.Timeout)
			defer cancel()

			res := s.Enumerate(ctx, domain, r.client)
			results[idx] = &res

			done := int(atomic.AddInt64(&completed, 1))
			if !r.cfg.Silent {
				r.printSourceResult(&res, done, total)
			}
		}(i, src)
	}

	wg.Wait()
	if !r.cfg.Silent {
		fmt.Fprintln(os.Stderr) // newline after final progress
	}
	return results
}

func (r *Runner) printSourceResult(res *sources.Result, done, total int) {
	ms := res.Duration.Milliseconds()
	switch {
	case res.Skipped:
		fmt.Fprintf(os.Stderr, "\r  %s⊘%s %-15s skipped (not installed)\n",
			colorYellow, colorReset, res.Name)
	case res.Err != nil && len(res.Domains) == 0:
		fmt.Fprintf(os.Stderr, "\r  %s✗%s %-15s 0 domains (%dms)\n",
			colorRed, colorReset, res.Name, ms)
	case len(res.Domains) == 0:
		fmt.Fprintf(os.Stderr, "\r  %s⚠%s %-15s 0 domains (%dms) [att:%d]\n",
			colorYellow, colorReset, res.Name, ms, res.Attempts)
	default:
		fmt.Fprintf(os.Stderr, "\r  %s⚡%s %-15s %4d domains (%dms) [att:%d]\n",
			colorGreen, colorReset, res.Name, len(res.Domains), ms, res.Attempts)
	}
	r.printProgress(done, total)
}

func (r *Runner) printProgress(done, total int) {
	const width = 30
	filled := 0
	pct := 0
	if total > 0 {
		filled = done * width / total
		pct = done * 100 / total
	}
	bar := make([]byte, width)
	for i := range bar {
		if i < filled {
			bar[i] = '#'
		} else {
			bar[i] = '-'
		}
	}
	fmt.Fprintf(os.Stderr, "\r  %s[%s%s%s%s]%s %3d%% (%d/%d)",
		colorBold,
		colorGreen, string(bar[:filled]),
		colorReset+colorBold, string(bar[filled:]),
		colorReset,
		pct, done, total)
}

func (r *Runner) logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

// CheckExternalTools reports the installation status of optional binaries.
func CheckExternalTools() {
	type tool struct {
		name    string
		install string
	}
	tools := []tool{
		{"subfinder", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"assetfinder", "go install github.com/tomnomnom/assetfinder@latest"},
		{"findomain", "https://github.com/Findomain/Findomain/releases"},
		{"anew", "go install github.com/tomnomnom/anew@latest"},
	}

	fmt.Fprintln(os.Stderr, colorBold+"[*] External Tool Status:"+colorReset)
	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err == nil {
			fmt.Fprintf(os.Stderr, "  %s✓%s %-15s installed\n", colorGreen, colorReset, t.name)
		} else {
			fmt.Fprintf(os.Stderr, "  %s✗%s %-15s missing  →  install: %s\n", colorRed, colorReset, t.name, t.install)
		}
	}
}

// AnewDedup pipes lines through `anew` binary if available, returning unique lines.
// Falls back to in-memory dedup when anew is not installed.
func AnewDedup(lines []string, appendFile string) []string {
	if _, err := exec.LookPath("anew"); err != nil {
		// anew not available — in-memory dedup is already done upstream
		return lines
	}

	args := []string{}
	if appendFile != "" {
		args = append(args, appendFile)
	}
	cmd := exec.Command("anew", args...)

	var in strings.Builder
	for _, l := range lines {
		in.WriteString(l + "\n")
	}
	cmd.Stdin = strings.NewReader(in.String())

	out, err := cmd.Output()
	if err != nil {
		// anew failed — return original
		return lines
	}

	var result []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}
