package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HackerTarget queries api.hackertarget.com for subdomain enumeration.
type HackerTarget struct{}

func (h *HackerTarget) Name() string { return "hackertarget" }

func (h *HackerTarget) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return h.fetch(ctx, domain, client)
	})
	return Result{
		Name:     h.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (h *HackerTarget) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hackertarget returned %d", resp.StatusCode)
	}

	suffix := "." + domain
	seen := make(map[string]bool)

	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "error") || strings.HasPrefix(line, "API") {
			continue
		}
		// Format: subdomain.example.com,1.2.3.4
		parts := strings.SplitN(line, ",", 2)
		host := strings.ToLower(strings.TrimSpace(parts[0]))
		if host != "" && (strings.HasSuffix(host, suffix) || host == domain) {
			seen[host] = true
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, sc.Err()
}
