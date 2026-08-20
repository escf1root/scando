package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// URLScan queries urlscan.io search API with pagination and list extraction.
type URLScan struct{}

func (u *URLScan) Name() string { return "urlscan" }

func (u *URLScan) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return u.fetch(ctx, domain, client)
	})
	return Result{
		Name:     u.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (u *URLScan) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	seen := make(map[string]bool)
	suffix := "." + domain

	baseURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", domain)

	fetchPage := func(url string) (int, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("User-Agent", "Scando-Enumeration-Tool/3.0")

		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return 0, fmt.Errorf("urlscan returned %d", resp.StatusCode)
		}

		var data struct {
			Total   int `json:"total"`
			Results []struct {
				Page struct {
					Domain string `json:"domain"`
					Url    string `json:"url"`
				} `json:"page"`
				Lists struct {
					Domains   []string `json:"domains"`
					Ips       []string `json:"ips"`
					Urls      []string `json:"urls"`
				} `json:"lists"`
				Task struct {
					Domain string `json:"domain"`
				} `json:"task"`
			} `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return 0, err
		}

		addIfValid := func(d string) {
			d = strings.ToLower(strings.TrimSpace(d))
			if d != "" && (strings.HasSuffix(d, suffix) || d == domain) {
				seen[d] = true
			}
		}

		for _, r := range data.Results {
			// Extract from page.domain
			addIfValid(r.Page.Domain)
			// Extract from task.domain
			addIfValid(r.Task.Domain)
			// Extract from lists.domains (richest source)
			for _, d := range r.Lists.Domains {
				addIfValid(d)
			}
		}
		return data.Total, nil
	}

	total, err := fetchPage(baseURL)
	if err != nil {
		return nil, err
	}

	// Paginate up to 5 pages (500 results) for large targets
	if total > 100 {
		maxPages := total/100 + 1
		if maxPages > 5 {
			maxPages = 5
		}
		for page := 2; page <= maxPages; page++ {
			pageURL := fmt.Sprintf("%s&page=%d", baseURL, page)
			if _, err := fetchPage(pageURL); err != nil {
				break
			}
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}

