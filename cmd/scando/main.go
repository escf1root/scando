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

	"github.com/escf1root/scando/internal/output"
	"github.com/escf1root/scando/internal/runner"
)

const version = "3.0.0"

const banner = `
                                        __          
                                      /\ \           
      ____    ___     __        ___   \_\ \    ___
     /',__\  /'___\ /'__ \    /' _ \   /'_ \  / __ \
    /\__,  \/\ \__//\ \L\.\_ /\ \/\ \/\ \L\ \/\ \L\ \
     \/\____/\ \____\ \__/.\_\  \_\ \_\ \___,_\ \____/
      \/___/  \/____/\/__/\/_/ \/_/\/_/\/__,_ /\/___/
`

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
		fmt.Fprintln(os.Stderr, "\033[1m\033[36m[*] Updating scando to the latest version via go install...\033[0m")
		cmd := os.Getenv("GO")
		if cmd == "" {
			cmd = "go"
		}
		execCmd := exec.Command(cmd, "install", "-v", "github.com/escf1root/scando/cmd/scando@latest")
		execCmd.Stdout = os.Stdout
		execCmd.Stderr = os.Stderr
		if err := execCmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "\033[31m[!] Update failed: %v\033[0m\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "\033[1m\033[32m[+] Successfully updated scando to latest version!\033[0m")
		os.Exit(0)
	}

	// ─── Banner ──────────────────────────────────────────────────────────────
	if !*silent {
		fmt.Fprint(os.Stderr, "\033[1m\033[36m")
		fmt.Fprintln(os.Stderr, banner)
		fmt.Fprintf(os.Stderr, "\033[0m  \033[1mScando v%s\033[0m — Parallel Domain Enumeration\n\n", version)
	}

	// ─── Check tools mode ────────────────────────────────────────────────────
	if *checkTools {
		runner.CheckExternalTools()
		os.Exit(0)
	}

	// ─── Validate domain ─────────────────────────────────────────────────────
	*domain = strings.ToLower(strings.TrimSpace(*domain))
	if *domain == "" {
		// interactive prompt
		if !*silent {
			fmt.Fprint(os.Stderr, "  Enter target domain: ")
		}
		fmt.Scan(domain)
		*domain = strings.ToLower(strings.TrimSpace(*domain))
	}

	if !domainRe.MatchString(*domain) {
		fatalf("Invalid domain format: %q\n", *domain)
	}

	// ─── Scan folder ─────────────────────────────────────────────────────────
	if *folderName == "" {
		safe := strings.ReplaceAll(*domain, ".", "_")
		*folderName = safe + "_parallel"
	}

	scriptDir, _ := os.Getwd()
	scanDir := filepath.Join(scriptDir, "scans", *folderName)

	// ─── Build runner config ─────────────────────────────────────────────────
	cfg := runner.Config{
		Timeout:     time.Duration(*timeout) * time.Second,
		MaxParallel: *parallel,
		Silent:      *silent,
	}

	if !*silent {
		fmt.Fprintf(os.Stderr, "  \033[1m[*]\033[0m Domain     : %s\n", *domain)
		fmt.Fprintf(os.Stderr, "  \033[1m[*]\033[0m Scan dir   : %s\n", scanDir)
		fmt.Fprintf(os.Stderr, "  \033[1m[*]\033[0m Output     : %s\n", *outFile)
		fmt.Fprintf(os.Stderr, "  \033[1m[*]\033[0m Parallel   : %d\n", *parallel)
		fmt.Fprintf(os.Stderr, "  \033[1m[*]\033[0m Timeout/src: %ds\n\n", *timeout)
		runner.CheckExternalTools()
		fmt.Fprintln(os.Stderr)
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
		fatalf("Output error: %v\n", err)
	}

	// Optional anew piping if requested
	if *useAnew {
		outPath := filepath.Join(scanDir, *outFile)
		if data, readErr := os.ReadFile(outPath); readErr == nil {
			lines := strings.Split(string(data), "\n")
			_ = runner.AnewDedup(lines, "")
		}
	}

	// ─── Print results ───────────────────────────────────────────────────────
	if *silent {
		// In silent mode: stream final deduplicated domains to stdout
		outPath := filepath.Join(scanDir, *outFile)
		data, readErr := os.ReadFile(outPath)
		if readErr == nil {
			os.Stdout.Write(data)
		}
	} else {
		output.PrintReport(results, opts, total)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\033[31m[!]\033[0m "+format, args...)
	os.Exit(1)
}
