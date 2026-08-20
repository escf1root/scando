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

// Options controls what output.Write produces.
type Options struct {
	Domain      string
	ScanDir     string        // root scan directory (scans/<name>/)
	OutputFile  string        // final merged subdomains file (just filename)
	MaxParallel int
	TotalTime   time.Duration
	Silent      bool
}

// Write deduplicates all results and writes ONLY the final output file.
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

	// Write merged output (only final subdomains file)
	outPath := filepath.Join(opts.ScanDir, opts.OutputFile)
	if err := writeLines(outPath, filtered); err != nil {
		return 0, fmt.Errorf("write output: %w", err)
	}

	return len(filtered), nil
}

// PrintReport prints the final human-readable summary to stderr.
func PrintReport(results []*sources.Result, opts Options, total int) {
	const sep = "══════════════════════════════════════════════════════"
	fmt.Fprintf(os.Stderr, "\n\033[1m\033[32m%s\033[0m\n", sep)
	fmt.Fprintf(os.Stderr, "\033[1mDomain         :\033[0m %s\n", opts.Domain)
	fmt.Fprintf(os.Stderr, "\033[1mTotal Subdomains:\033[0m %d\n", total)
	fmt.Fprintf(os.Stderr, "\033[1mTotal Time     :\033[0m %s\n", opts.TotalTime.Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "\033[1mOutput         :\033[0m %s\n",
		filepath.Join(opts.ScanDir, opts.OutputFile))

	fmt.Fprintln(os.Stderr, "\n\033[1m\033[35mTool Performance:\033[0m")
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

	for _, name := range order {
		res, ok := byName[name]
		if !ok {
			continue
		}
		ms := res.Duration.Milliseconds()
		switch {
		case res.Skipped:
			fmt.Fprintf(os.Stderr, "  \033[33m⊘\033[0m %-15s  skipped\n", name)
		case len(res.Domains) > 0:
			fmt.Fprintf(os.Stderr, "  \033[32m⚡\033[0m %-15s  %4d domains  (%dms)\n", name, len(res.Domains), ms)
		default:
			fmt.Fprintf(os.Stderr, "  \033[33m⚠\033[0m %-15s  %4d domains  (%dms)\n", name, len(res.Domains), ms)
		}
	}
	// Catch any extra results not in order slice
	for _, res := range results {
		if res != nil {
			found := false
			for _, name := range order {
				if name == res.Name {
					found = true
					break
				}
			}
			if !found {
				ms := res.Duration.Milliseconds()
				fmt.Fprintf(os.Stderr, "  \033[32m⚡\033[0m %-15s  %4d domains  (%dms)\n", res.Name, len(res.Domains), ms)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\033[1m\033[32m%s\033[0m\n\n", sep)
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
