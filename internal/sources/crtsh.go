package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CrtSh queries certificate transparency logs at crt.sh.
type CrtSh struct{}

func (c *CrtSh) Name() string { return "crtsh" }

func (c *CrtSh) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return c.fetch(ctx, domain, client)
	})
	return Result{
		Name:     c.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

func (c *CrtSh) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	endpoints := []string{
		fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain),
		fmt.Sprintf("https://crt.sh/?q=.%s&output=json", domain),
	}

	seen := make(map[string]bool)
	suffix := "." + domain

	for _, rawURL := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			var entries []struct {
				NameValue string `json:"name_value"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&entries); err == nil {
				for _, e := range entries {
					for _, name := range strings.Split(e.NameValue, "\n") {
						name = strings.ToLower(strings.TrimSpace(name))
						// Strip wildcards and normalize
						name = strings.ReplaceAll(name, "*.", "")
						if name != "" && (strings.HasSuffix(name, suffix) || name == domain) {
							seen[name] = true
						}
					}
				}
			}
			resp.Body.Close()
		} else {
			resp.Body.Close()
		}
	}

	// Recursive HTML fallback for wildcards and deeper results
	c.fetchHTML(ctx, domain, client, seen)

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, nil
}

func (c *CrtSh) fetchHTML(ctx context.Context, domain string, client *http.Client, seen map[string]bool) {
	htmlURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", htmlURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	re := regexp.MustCompile(`[a-zA-Z0-9.-]+\.` + regexp.QuoteMeta(domain))
	matches := re.FindAllString(content, -1)
	suffix := "." + domain
	for _, m := range matches {
		m = strings.ToLower(strings.TrimPrefix(m, "*."))
		if strings.HasSuffix(m, suffix) || m == domain {
			seen[m] = true
		}
	}
}
