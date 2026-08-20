package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OTX queries AlienVault Open Threat Exchange passive DNS with pagination.
type OTX struct{}

func (o *OTX) Name() string { return "otx" }

func (o *OTX) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return o.fetch(ctx, domain, client)
	})
	return Result{
		Name:     o.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (o *OTX) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	seen := make(map[string]bool)
	suffix := "." + domain
	const pageSize = 50

	page := 1
	for {
		url := fmt.Sprintf(
			"https://otx.alienvault.com/api/v1/indicators/hostname/%s/passive_dns?page=%d&limit=%d",
			domain, page, pageSize,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("OTX returned status code %d", resp.StatusCode)
		}

		var data struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		for _, entry := range data.PassiveDNS {
			h := strings.ToLower(strings.TrimSpace(entry.Hostname))
			if h != "" && (strings.HasSuffix(h, suffix) || h == domain) {
				seen[h] = true
			}
		}

		// Stop if fewer results than page size — no more pages
		if len(data.PassiveDNS) < pageSize {
			break
		}
		page++

		// Guard: max 10 pages to avoid infinite loop
		if page > 10 {
			break
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}
