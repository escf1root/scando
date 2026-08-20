package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// RapidDNS queries rapiddns.io for subdomain enumeration.
type RapidDNS struct{}

func (r *RapidDNS) Name() string { return "rapiddns" }

func (r *RapidDNS) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
	start := time.Now()
	domains, attempts, err := retry(3, 3*time.Second, func() ([]string, error) {
		return r.fetch(ctx, domain, client)
	})
	return Result{
		Name:     r.Name(),
		Domains:  dedup(domains),
		Duration: time.Since(start),
		Attempts: attempts,
		Err:      err,
	}
}

var rapidDNSRe = regexp.MustCompile(`[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}`)

func (r *RapidDNS) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	// Try the plain-text download endpoint first
	urls := []string{
		fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain),
		fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain),
	}

	suffix := "." + domain
	seen := make(map[string]bool)

	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			re := regexp.MustCompile(`[a-zA-Z0-9._-]+\.` + regexp.QuoteMeta(domain))
			sc := bufio.NewScanner(resp.Body)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				line := sc.Text()
				for _, m := range re.FindAllString(line, -1) {
					m = strings.ToLower(m)
					if strings.HasSuffix(m, suffix) || m == domain {
						seen[m] = true
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
