package runner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/escf1root/scando/v3/internal/sources"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorBGreen  = "\033[92m" // bright green
	colorBCyan   = "\033[96m" // bright cyan
)

// Config controls runner behaviour.
type Config struct {
	Timeout     time.Duration
	MaxParallel int
	Silent      bool
}

// DefaultConfig returns production defaults.
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
		// Passive OSINT APIs
		&sources.CrtSh{},
		&sources.OTX{},
		&sources.URLScan{},
		&sources.WebArchive{},
		&sources.HackerTarget{},
		&sources.ThreatMiner{},
		&sources.RapidDNS{},
		// External tool wrappers — skipped when binary absent
		&sources.Subfinder{},
		&sources.Assetfinder{},
		&sources.Findomain{},
	}

	return &Runner{cfg: cfg, client: client, sources: srcs}
}

// Run executes all sources in parallel and returns collected results.
func (r *Runner) Run(ctx context.Context, domain string) []*sources.Result {
	total := len(r.sources)
	results := make([]*sources.Result, total)
	var completed int64

	sem := make(chan struct{}, r.cfg.MaxParallel)
	var wg sync.WaitGroup

	if !r.cfg.Silent {
		r.printSectionHeader(total)
		r.printProgress(0, total)
	}

	for i, src := range r.sources {
		wg.Add(1)
		go func(idx int, s sources.Source) {
			defer wg.Done()
			
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = &sources.Result{
					Name:    s.Name(),
					Err:     ctx.Err(),
					Skipped: false,
				}
				done := int(atomic.AddInt64(&completed, 1))
				if !r.cfg.Silent {
					r.printSourceResult(results[idx], done, total)
				}
				return
			}

			runCtx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
			defer cancel()

			res := s.Enumerate(runCtx, domain, r.client)
			results[idx] = &res

			done := int(atomic.AddInt64(&completed, 1))
			if !r.cfg.Silent {
				r.printSourceResult(&res, done, total)
			}
		}(i, src)
	}

	wg.Wait()
	if !r.cfg.Silent {
		// clear progress bar line
		fmt.Fprint(os.Stderr, "\033[2K\r")
	}
	return results
}

func (r *Runner) printSectionHeader(total int) {
	fmt.Fprintf(os.Stderr, "  %s●%s Scanning with %s%d sources%s  %s(parallel=%d  timeout=%s)%s\n\n",
		colorBold+colorBCyan, colorReset,
		colorBold, total, colorReset,
		colorDim, r.cfg.MaxParallel, r.cfg.Timeout, colorReset,
	)
}

func (r *Runner) printSourceResult(res *sources.Result, done, total int) {
	ms := res.Duration.Milliseconds()
	// Clear the progress bar line before printing result
	fmt.Fprint(os.Stderr, "\033[2K\r")

	switch {
	case res.Skipped:
		fmt.Fprintf(os.Stderr, "  %s○%s  %-14s  %sskipped%s\n",
			colorDim+colorYellow, colorReset,
			res.Name,
			colorDim, colorReset)

	case res.Err != nil && len(res.Domains) == 0:
		fmt.Fprintf(os.Stderr, "  %s✗%s  %-14s  %s0 subdomains%s  %s%dms%s\n",
			colorBold+colorRed, colorReset,
			res.Name,
			colorDim, colorReset,
			colorDim, ms, colorReset)

	case len(res.Domains) == 0:
		fmt.Fprintf(os.Stderr, "  %s–%s  %-14s  %s0 subdomains%s  %s%dms%s\n",
			colorDim+colorYellow, colorReset,
			res.Name,
			colorDim, colorReset,
			colorDim, ms, colorReset)

	default:
		fmt.Fprintf(os.Stderr, "  %s✔%s  %-14s  %s%4d subdomains%s  %s%dms%s\n",
			colorBold+colorBGreen, colorReset,
			res.Name,
			colorBold, len(res.Domains), colorReset,
			colorDim, ms, colorReset)
	}

	r.printProgress(done, total)
}

func (r *Runner) printProgress(done, total int) {
	const barWidth = 32
	filled := 0
	pct := 0
	if total > 0 {
		filled = done * barWidth / total
		pct = done * 100 / total
	}

	// Build filled and empty parts separately (█ and ░ are 3-byte UTF-8 runes)
	var filledPart, emptyPart strings.Builder
	for i := 0; i < barWidth; i++ {
		if i < filled {
			filledPart.WriteString("█")
		} else {
			emptyPart.WriteString("░")
		}
	}

	fmt.Fprintf(os.Stderr, "\033[2K\r  %s%s%s%s%s  %s%3d%%%s  %s%d/%d%s",
		colorBold+colorBCyan, filledPart.String(),
		colorDim, emptyPart.String(), colorReset,
		colorBold, pct, colorReset,
		colorDim, done, total, colorReset,
	)
}

// CheckExternalTools reports the installation status of optional binaries.
func CheckExternalTools() {
	type tool struct {
		name    string
		install string
	}
	tools := []tool{
		{"subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
		{"assetfinder", "go install github.com/tomnomnom/assetfinder@latest"},
		{"findomain", "https://github.com/Findomain/Findomain/releases"},
		{"anew", "go install github.com/tomnomnom/anew@latest"},
	}

	fmt.Fprintf(os.Stderr, "  %s◆ External Tools%s\n", colorBold+colorMagenta, colorReset)
	for _, t := range tools {
		if _, err := exec.LookPath(t.name); err == nil {
			fmt.Fprintf(os.Stderr, "  %s✔%s  %-14s  %sinstalled%s\n",
				colorBold+colorBGreen, colorReset, t.name, colorDim, colorReset)
		} else {
			fmt.Fprintf(os.Stderr, "  %s–%s  %-14s  %snot found%s\n",
				colorDim+colorYellow, colorReset, t.name, colorDim, colorReset)
		}
	}
}

// AnewDedup pipes lines through `anew` binary if available.
func AnewDedup(lines []string, appendFile string) []string {
	if _, err := exec.LookPath("anew"); err != nil {
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
