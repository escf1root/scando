package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// BufferOver queries dns.bufferover.run for subdomain enumeration.
type BufferOver struct{}

func (b *BufferOver) Name() string { return "bufferover" }

func (b *BufferOver) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return b.fetch(ctx, domain, client)
	})
	return Result{
		Name:     b.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (b *BufferOver) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	url := fmt.Sprintf("https://dns.bufferover.run/dns?q=.%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Scando/3.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("bufferover returned %d", resp.StatusCode)
	}

	var data struct {
		FDNS []string `json:"FDNS_A"`
		RDNS []string `json:"RDNS"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	suffix := "." + domain
	seen := make(map[string]bool)

	parseLine := func(line string) {
		// Format: "IP,hostname" or just "hostname"
		parts := strings.SplitN(line, ",", 2)
		var host string
		if len(parts) == 2 {
			host = strings.ToLower(strings.TrimSpace(parts[1]))
		} else {
			host = strings.ToLower(strings.TrimSpace(parts[0]))
		}
		if host != "" && (strings.HasSuffix(host, suffix) || host == domain) {
			seen[host] = true
		}
	}

	for _, line := range data.FDNS {
		parseLine(line)
	}
	for _, line := range data.RDNS {
		parseLine(line)
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}
