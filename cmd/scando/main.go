package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/escf1root/scando/v3/internal/output"
	"github.com/escf1root/scando/v3/internal/runner"
)

const version = "3.0.9"

// ANSI codes
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	cyan    = "\033[36m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	red     = "\033[31m"
	magenta = "\033[35m"
	blue    = "\033[34m"
	bCyan   = "\033[96m"  // bright cyan
	bGreen  = "\033[92m"  // bright green
	bYellow = "\033[93m"  // bright yellow
)

const banner = `
  ███████╗ ██████╗ █████╗ ███╗  ██╗██████╗  ██████╗
  ██╔════╝██╔════╝██╔══██╗████╗ ██║██╔══██╗██╔═══██╗
  ███████╗██║     ███████║██╔██╗██║██║  ██║██║   ██║
  ╚════██║██║     ██╔══██║██║╚████║██║  ██║██║   ██║
  ███████║╚██████╗██║  ██║██║ ╚███║██████╔╝╚██████╔╝
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝╚═════╝  ╚═════╝`

var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func main() {
	// ─── Flags ───────────────────────────────────────────────────────────────
	domain := flag.String("d", "", "Target domain to scan")
	domainList := flag.String("f", "", "File containing list of domains to scan (one per line)")
	outFile := flag.String("o", "subdomains.txt", "Output filename (written to current directory)")
	timeout := flag.Int("t", 60, "Per-source timeout in seconds")
	parallel := flag.Int("p", 8, "Max parallel sources")
	silent := flag.Bool("silent", false, "Print only discovered domains to stdout")
	checkTools := flag.Bool("check", false, "Check external tool installation status and exit")
	useAnew := flag.Bool("anew", false, "Pipe final results through 'anew' binary if installed")
	showVersion := flag.Bool("version", false, "Print version and exit")
	updateSelf := flag.Bool("update", false, "Update scando to latest version via 'go install'")
	flag.Parse()

	// ─── Version ─────────────────────────────────────────────────────────────
	if *showVersion {
		fmt.Printf("scando v%s\n", version)
		os.Exit(0)
	}

	// ─── Self Update ─────────────────────────────────────────────────────────
	if *updateSelf {
		printHeader()
		eprintf("\n  %s↻%s  Updating scando to latest version...\n\n", bold+bCyan, reset)
		cmd := os.Getenv("GO")
		if cmd == "" {
			cmd = "go"
		}
		execCmd := exec.Command(cmd, "install", "-v", "github.com/escf1root/scando/v3/cmd/scando@latest")
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		if err := execCmd.Run(); err != nil {
			eprintf("\n  %s✗%s  Update failed: %v\n\n", bold+red, reset, err)
			os.Exit(1)
		}
		eprintf("\n  %s✔%s  Successfully updated to the latest version!\n\n", bold+bGreen, reset)
		os.Exit(0)
	}

	// ─── Banner ──────────────────────────────────────────────────────────────
	if !*silent {
		printHeader()
	}

	// ─── Check tools mode ────────────────────────────────────────────────────
	if *checkTools {
		runner.CheckExternalTools()
		os.Exit(0)
	}

	// ─── Parse Domains to Scan ───────────────────────────────────────────────
	var domainsToScan []string
	if *domainList != "" {
		var err error
		domainsToScan, err = readLines(*domainList)
		if err != nil {
			eprintf("\n  %s✗%s Failed to read domain list file: %v\n\n", bold+red, reset, err)
			os.Exit(1)
		}
		if len(domainsToScan) == 0 {
			eprintf("\n  %s✗%s Domain list file is empty\n\n", bold+red, reset)
			os.Exit(1)
		}
	} else {
		*domain = cleanDomain(*domain)
		if *domain == "" {
			if !*silent {
				eprintf("  %s┌%s Enter target domain%s\n", dim+cyan, reset, reset)
				eprintf("  %s└─›%s ", bold+cyan, reset)
			}
			fmt.Scan(domain)
			*domain = cleanDomain(*domain)
			if !*silent {
				eprintf("\n")
			}
		}
		if *domain == "" || !domainRe.MatchString(*domain) {
			eprintf("\n  %s✗%s Invalid domain format: %q\n\n", bold+red, reset, *domain)
			os.Exit(1)
		}
		domainsToScan = []string{*domain}
	}

	// ─── Output directory setup ──────────────────────────────────────────────
	scanDir, _ := os.Getwd()
	outPath := filepath.Join(scanDir, *outFile)
	
	// Delete file first to start fresh (unless -anew is used, but we handle anew later)
	_ = os.Remove(outPath)

	// ─── Graceful CTRL+C Handler ─────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ─── Global State ────────────────────────────────────────────────────────
	allSubdomains := make(map[string]bool)

	// Stream final unique subdomains to stdout in silent mode upon exit
	defer func() {
		if *silent {
			list := make([]string, 0, len(allSubdomains))
			for s := range allSubdomains {
				list = append(list, s)
			}
			sort.Strings(list)
			for _, s := range list {
				fmt.Println(s)
			}
		}
	}()

	// ─── Build runner config ──────────────────────────────────────────────────
	cfg := runner.Config{
		Timeout:     time.Duration(*timeout) * time.Second,
		MaxParallel: *parallel,
		Silent:      *silent,
	}

	if !*silent {
		targetDesc := *domain
		if *domainList != "" {
			targetDesc = fmt.Sprintf("List: %s (%d domains)", *domainList, len(domainsToScan))
		}
		printScanInfo(targetDesc, scanDir, *outFile, *parallel, *timeout)
		runner.CheckExternalTools()
		eprintf("\n")
	}

	// ─── Main Scan Loop ──────────────────────────────────────────────────────
	for _, currentDomain := range domainsToScan {
		if ctx.Err() != nil {
			break
		}

		currentDomain = cleanDomain(currentDomain)
		if currentDomain == "" || !domainRe.MatchString(currentDomain) {
			if !*silent {
				eprintf("  %s⚠%s Skipping invalid domain: %q\n\n", bold+yellow, reset, currentDomain)
			}
			continue
		}

		if !*silent {
			eprintf("  %s┌──────────────────────────────────────────────────────┐%s\n", bold+cyan, reset)
			eprintf("  %s│%s  Target: %s%-45s%s %s│%s\n", bold+cyan, reset, bold, currentDomain, reset, bold+cyan, reset)
			eprintf("  %s└──────────────────────────────────────────────────────┘%s\n\n", bold+cyan, reset)
		}

		totalStart := time.Now()
		r := runner.New(cfg)
		results := r.Run(ctx, currentDomain)
		totalTime := time.Since(totalStart)

		// Filter results and add to allSubdomains
		suffix := "." + currentDomain
		domainFoundCount := 0
		for _, res := range results {
			if res == nil {
				continue
			}
			for _, d := range res.Domains {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" {
					if strings.HasSuffix(d, suffix) || d == currentDomain {
						if !allSubdomains[d] {
							allSubdomains[d] = true
							domainFoundCount++
						}
					}
				}
			}
		}

		// Write accumulated subdomains immediately
		if err := saveSubdomains(outPath, allSubdomains); err != nil {
			eprintf("  %s✗%s Failed to save subdomains: %v\n", bold+red, reset, err)
		}

		// Print Report for this target
		if !*silent {
			opts := output.Options{
				Domain:      currentDomain,
				ScanDir:     scanDir,
				OutputFile:  *outFile,
				MaxParallel: *parallel,
				TotalTime:   totalTime,
				Silent:      *silent,
			}
			output.PrintReport(results, opts, domainFoundCount)
		}

		if ctx.Err() != nil {
			break
		}
	}

	// Interrupted message
	if ctx.Err() != nil && !*silent {
		eprintf("  %s[!] Scan interrupted by user. Saved %d total subdomains to %s.%s\n\n",
			bold+bYellow, len(allSubdomains), *outFile, reset)
	}

	// ─── Optional anew piping ────────────────────────────────────────────────
	if *useAnew {
		if data, readErr := os.ReadFile(outPath); readErr == nil {
			lines := strings.Split(string(data), "\n")
			_ = runner.AnewDedup(lines, "")
		}
	}
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func eprintf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func printHeader() {
	eprintf("%s%s%s\n", bold+bCyan, banner, reset)
	eprintf("  %s%s v%s%s  %s—  Parallel Subdomain Enumeration%s\n\n",
		bold+bGreen, "Scando", version, reset,
		dim, reset)
}

func printScanInfo(domain, scanDir, outFile string, parallel, timeout int) {
	const lineW = 54
	line := strings.Repeat("─", lineW)

	row := func(label, value string) {
		fmt.Fprintf(os.Stderr, "  %s│%s  %-14s %s%-*s%s%s│%s\n",
			bold+cyan, reset,
			bold+label+reset,
			dim, lineW-17, value, reset,
			bold+cyan, reset,
		)
	}

	eprintf("  %s┌%s%s%s┐%s\n", bold+cyan, reset, line, bold+cyan, reset)
	row("Target",   domain)
	row("Output",   outFile+" (current directory)")
	row("Parallel", fmt.Sprintf("%d sources", parallel))
	row("Timeout",  fmt.Sprintf("%ds / source", timeout))
	eprintf("  %s└%s%s%s┘%s\n\n", bold+cyan, reset, line, bold+cyan, reset)
}

func cleanDomain(raw string) string {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[:idx]
	}
	return strings.TrimSpace(d)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func saveSubdomains(filePath string, subdomains map[string]bool) error {
	list := make([]string, 0, len(subdomains))
	for s := range subdomains {
		list = append(list, s)
	}
	sort.Strings(list)

	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, s := range list {
		fmt.Fprintln(f, s)
	}
	return nil
}
