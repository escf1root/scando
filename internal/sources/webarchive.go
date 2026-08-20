package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// WebArchive queries the Wayback Machine CDX API.
type WebArchive struct{}

func (w *WebArchive) Name() string { return "webarchive" }

func (w *WebArchive) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return w.fetch(ctx, domain, client)
	})
	return Result{
		Name:     w.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

var hostRegex = regexp.MustCompile(`(?i)(?:https?://)?([a-zA-Z0-9._-]+)`)

func (w *WebArchive) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	seen := make(map[string]bool)
	suffix := "." + domain

	endpoints := []string{
		"https://web.archive.org/cdx/search/cdx",
		"http://web.archive.org/cdx/search/cdx",
	}

	params := url.Values{
		"url":      {"*." + domain + "/*"},
		"output":   {"json"},
		"collapse": {"urlkey"},
		"limit":    {"5000"},
		"fl":       {"original"},
	}

	extractFromURLs := func(rawURLs []string) {
		re := regexp.MustCompile(`(?i)(?:https?://)?([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
		for _, rawURL := range rawURLs {
			m := re.FindStringSubmatch(rawURL)
			if len(m) > 1 {
				h := strings.ToLower(m[1])
				if strings.HasSuffix(h, suffix) || h == domain {
					seen[h] = true
				}
			}
		}
	}

	for _, endpoint := range endpoints {
		reqURL := fmt.Sprintf("%s?%s", endpoint, params.Encode())
		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			// CDX JSON: [[header], [row1], [row2], ...]
			var rows [][]string
			decodeErr := json.NewDecoder(resp.Body).Decode(&rows)
			resp.Body.Close()

			if decodeErr == nil && len(rows) > 1 {
				rawURLs := make([]string, 0, len(rows)-1)
				for _, row := range rows[1:] {
					if len(row) > 0 {
						rawURLs = append(rawURLs, row[0])
					}
				}
				extractFromURLs(rawURLs)
			}
		} else {
			resp.Body.Close()
		}

		if len(seen) > 0 {
			break
		}
	}

	// Timemap fallback for when CDX returns nothing
	if len(seen) == 0 {
		timemapURL := fmt.Sprintf("https://web.archive.org/web/timemap/json?url=%s&matchType=domain&output=json", domain)
		req, err := http.NewRequestWithContext(ctx, "GET", timemapURL, nil)
		if err == nil {
			req.Header.Set("User-Agent", "Mozilla/5.0")
			resp, err := client.Do(req)
			if err == nil && resp.StatusCode == 200 {
				var data [][]string
				if json.NewDecoder(resp.Body).Decode(&data) == nil {
					re := regexp.MustCompile(`([a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain) + `)`)
					for _, row := range data[1:] {
						if len(row) > 2 {
							m := re.FindStringSubmatch(row[2])
							if len(m) > 1 {
								seen[strings.ToLower(m[1])] = true
							}
						}
					}
				}
				resp.Body.Close()
			}
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}
