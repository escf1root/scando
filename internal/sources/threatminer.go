package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ThreatMiner queries api.threatminer.org for subdomain enumeration.
type ThreatMiner struct{}

func (t *ThreatMiner) Name() string { return "threatminer" }

func (t *ThreatMiner) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return t.fetch(ctx, domain, client)
	})
	return Result{
		Name:     t.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (t *ThreatMiner) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	targets := []string{domain}
	if root := GetRootDomain(domain); root != domain {
		targets = append(targets, root)
	}

	seen := make(map[string]bool)
	suffix := "." + domain

	for _, target := range targets {
		url := fmt.Sprintf("https://api.threatminer.org/v2/domain.php?q=%s&rt=5", target)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var data struct {
				StatusCode string   `json:"status_code"`
				Results    []string `json:"results"`
			}
			if json.NewDecoder(resp.Body).Decode(&data) == nil {
				for _, h := range data.Results {
					h = strings.ToLower(strings.TrimSpace(h))
					if h != "" && (strings.HasSuffix(h, suffix) || h == domain) {
						seen[h] = true
					}
				}
			}
			resp.Body.Close()
		} else {
			resp.Body.Close()
		}

		if len(seen) > 0 {
			break
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}
