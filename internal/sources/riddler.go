package sources

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Riddler queries riddler.io CSV export for subdomain enumeration.
type Riddler struct{}

func (r *Riddler) Name() string { return "riddler" }

func (r *Riddler) Enumerate(ctx context.Context, domain string, client *http.Client) Result {
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

func (r *Riddler) fetch(ctx context.Context, domain string, client *http.Client) ([]string, error) {
	rootDomain := GetRootDomain(domain)
	url := fmt.Sprintf("https://riddler.io/search/exportcsv?q=pld:%s", rootDomain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/csv,text/plain,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("riddler returned %d", resp.StatusCode)
	}

	suffix := "." + domain
	seen := make(map[string]bool)

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		if lineNum == 1 {
			// Skip CSV header
			continue
		}
		line := sc.Text()
		// CSV format: Date,IP,Host,Pld,Tags,...
		// Host is column index 2 (0-indexed)
		parts := strings.Split(line, ",")
		if len(parts) >= 3 {
			host := strings.ToLower(strings.TrimSpace(parts[2]))
			if host != "" && (strings.HasSuffix(host, suffix) || host == domain) {
				seen[host] = true
			}
		}
	}

	result := make([]string, 0, len(seen))
	for d := range seen {
		result = append(result, d)
	}
	return result, sc.Err()
}
