package output

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/escf1root/scando/v3/internal/sources"
)

// ANSI codes
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	red     = "\033[31m"
	cyan    = "\033[36m"
	magenta = "\033[35m"
	bGreen  = "\033[92m"
	bCyan   = "\033[96m"
)

// Options controls what output.Write produces.
type Options struct {
	Domain      string
	ScanDir     string        // output directory (current working directory)
	OutputFile  string        // final merged subdomains file (just filename)
	MaxParallel int
	TotalTime   time.Duration
	Silent      bool
}

// Write deduplicates all results and writes the final output file.
func Write(results []*sources.Result, opts Options) (int, error) {
	// Collect & deduplicate
	seen := make(map[string]bool)
	for _, res := range results {
		if res == nil {
			continue
		}
		for _, d := range res.Domains {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" {
				seen[d] = true
			}
		}
	}

	// Sort
	merged := make([]string, 0, len(seen))
	for d := range seen {
		merged = append(merged, d)
	}
	sort.Strings(merged)

	// Filter: must end with .domain or equal domain
	suffix := "." + opts.Domain
	filtered := merged[:0]
	for _, d := range merged {
		if strings.HasSuffix(d, suffix) || d == opts.Domain {
			filtered = append(filtered, d)
		}
	}

	// Ensure output dir exists
	if err := os.MkdirAll(opts.ScanDir, 0755); err != nil {
		return 0, fmt.Errorf("mkdir scan dir: %w", err)
	}

	// Write merged output
	outPath := filepath.Join(opts.ScanDir, opts.OutputFile)
	if err := writeLines(outPath, filtered); err != nil {
		return 0, fmt.Errorf("write output: %w", err)
	}

	return len(filtered), nil
}

// PrintReport prints the final summary to stderr.
func PrintReport(results []*sources.Result, opts Options, total int) {
	const lineW = 54
	line := strings.Repeat("─", lineW)

	// ── Section header ────────────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n  %s◆ Results%s\n", bold+bCyan, reset)
	fmt.Fprintf(os.Stderr, "  %s┌%s%s%s┐%s\n", bold+cyan, reset, line, bold+cyan, reset)

	rowVal := func(label, value, valueColor string) {
		fmt.Fprintf(os.Stderr, "  %s│%s  %-16s %s%-*s%s%s│%s\n",
			bold+cyan, reset,
			bold+label+reset,
			valueColor, lineW-19, value, reset,
			bold+cyan, reset,
		)
	}

	rowVal("Domain",     opts.Domain,                               bold+bCyan)
	rowVal("Subdomains", fmt.Sprintf("%d found", total),            bold+bGreen)
	rowVal("Time",       opts.TotalTime.Round(time.Millisecond).String(), dim)
	rowVal("Saved to",   filepath.Join(opts.ScanDir, opts.OutputFile), dim)

	fmt.Fprintf(os.Stderr, "  %s└%s%s%s┘%s\n", bold+cyan, reset, line, bold+cyan, reset)

	// ── Per-source breakdown ──────────────────────────────────
	fmt.Fprintf(os.Stderr, "\n  %s◆ Source Breakdown%s\n", bold+magenta, reset)
	fmt.Fprintf(os.Stderr, "  %s┌%s%s%s┐%s\n", bold+cyan, reset, line, bold+cyan, reset)

	order := []string{
		"crtsh", "otx", "urlscan", "webarchive",
		"hackertarget", "threatminer", "rapiddns", "bufferover", "riddler",
		"subfinder", "assetfinder", "findomain",
	}

	byName := make(map[string]*sources.Result)
	for _, r := range results {
		if r != nil {
			byName[r.Name] = r
		}
	}

	printRow := func(name string, res *sources.Result) {
		ms := res.Duration.Milliseconds()
		switch {
		case res.Skipped:
			fmt.Fprintf(os.Stderr, "  %s│%s  %s○%s  %-14s  %s%-12s%s  %s%s│%s\n",
				bold+cyan, reset,
				dim+yellow, reset,
				name,
				dim, "skipped", reset,
				dim, strings.Repeat(" ", lineW-36), bold+cyan, reset)

		case len(res.Domains) > 0:
			count := fmt.Sprintf("%d subdomains", len(res.Domains))
			timing := fmt.Sprintf("%dms", ms)
			fmt.Fprintf(os.Stderr, "  %s│%s  %s✔%s  %-14s  %s%-20s%s  %s%6s%s  %s│%s\n",
				bold+cyan, reset,
				bold+bGreen, reset,
				name,
				bold, count, reset,
				dim, timing, reset,
				bold+cyan, reset)

		default:
			timing := fmt.Sprintf("%dms", ms)
			fmt.Fprintf(os.Stderr, "  %s│%s  %s–%s  %-14s  %s%-20s%s  %s%6s%s  %s│%s\n",
				bold+cyan, reset,
				dim, reset,
				name,
				dim, "0 subdomains", reset,
				dim, timing, reset,
				bold+cyan, reset)
		}
	}

	for _, name := range order {
		res, ok := byName[name]
		if !ok {
			continue
		}
		printRow(name, res)
	}
	// Extra results not in order list
	for _, res := range results {
		if res == nil {
			continue
		}
		inOrder := false
		for _, n := range order {
			if n == res.Name {
				inOrder = true
				break
			}
		}
		if !inOrder {
			printRow(res.Name, res)
		}
	}

	fmt.Fprintf(os.Stderr, "  %s└%s%s%s┘%s\n\n", bold+cyan, reset, line, bold+cyan, reset)
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
	return nil
}
