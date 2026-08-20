package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/escf1root/scando/v3/internal/output"
	"github.com/escf1root/scando/v3/internal/runner"
)

const version = "3.0.0"

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
	domain := flag.String("d", "", "Target domain (required)")
	outFile := flag.String("o", "subdomains.txt", "Output filename")
	folderName := flag.String("f", "", "Scan folder name (default: <domain>_parallel)")
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

	// ─── Validate domain ─────────────────────────────────────────────────────
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

	if !domainRe.MatchString(*domain) {
		eprintf("\n  %s✗%s Invalid domain: %q\n\n", bold+red, reset, *domain)
		os.Exit(1)
	}

	// ─── Scan folder ─────────────────────────────────────────────────────────
	if *folderName == "" {
		safe := strings.ReplaceAll(*domain, ".", "_")
		*folderName = safe + "_parallel"
	}

	scriptDir, _ := os.Getwd()
	scanDir := filepath.Join(scriptDir, "scans", *folderName)

	// ─── Build runner config ──────────────────────────────────────────────────
	cfg := runner.Config{
		Timeout:     time.Duration(*timeout) * time.Second,
		MaxParallel: *parallel,
		Silent:      *silent,
	}

	if !*silent {
		printScanInfo(*domain, scanDir, *outFile, *parallel, *timeout)
		runner.CheckExternalTools()
		eprintf("\n")
	}

	// ─── Run ─────────────────────────────────────────────────────────────────
	totalStart := time.Now()
	r := runner.New(cfg)
	results := r.Run(*domain)
	totalTime := time.Since(totalStart)

	// ─── Write output ─────────────────────────────────────────────────────────
	opts := output.Options{
		Domain:      *domain,
		ScanDir:     scanDir,
		OutputFile:  *outFile,
		MaxParallel: *parallel,
		TotalTime:   totalTime,
		Silent:      *silent,
	}

	total, err := output.Write(results, opts)
	if err != nil {
		eprintf("\n  %s✗%s  Output error: %v\n\n", bold+red, reset, err)
		os.Exit(1)
	}

	// Optional anew piping
	if *useAnew {
		outPath := filepath.Join(scanDir, *outFile)
		if data, readErr := os.ReadFile(outPath); readErr == nil {
			lines := strings.Split(string(data), "\n")
			_ = runner.AnewDedup(lines, "")
		}
	}

	// ─── Print results ────────────────────────────────────────────────────────
	if *silent {
		outPath := filepath.Join(scanDir, *outFile)
		data, readErr := os.ReadFile(outPath)
		if readErr == nil {
			os.Stdout.Write(data)
		}
	} else {
		output.PrintReport(results, opts, total)
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
	row("Output",   filepath.Join(scanDir, outFile))
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
