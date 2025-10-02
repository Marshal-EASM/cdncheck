package generate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/ipinfo/go/v2/ipinfo"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/cdncheck"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var cidrRegex = regexp.MustCompile(`[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/[0-9]{1,3}`)

// Compile returns the compiled form of an input structure
func (c *Categories) Compile(options *Options) (*cdncheck.InputCompiled, error) {
	compiled := &cdncheck.InputCompiled{
		CDN:    make(map[string][]string),
		WAF:    make(map[string][]string),
		Cloud:  make(map[string][]string),
		Common: make(map[string]map[string][]string),
	}

	// Fetch input items specified
	if c.CDN != nil {
		if err := c.CDN.fetchInputItem(options, compiled.CDN); err != nil {
			log.Printf("[err] could not fetch cdn item: %s\n", err)
		}
	}
	if c.WAF != nil {
		if err := c.WAF.fetchInputItem(options, compiled.WAF); err != nil {
			log.Printf("[err] could not fetch waf item: %s\n", err)
		}
	}
	if c.Cloud != nil {
		if err := c.Cloud.fetchInputItem(options, compiled.Cloud); err != nil {
			log.Printf("[err] could not fetch cloud item: %s\n", err)
		}
	}

	if c.Common != nil {
		compiled.Common = c.Common.FQDN
	}

	// Fetch custom scraper data and merge
	for dataType, scraper := range scraperTypeToScraperMap {
		var data map[string][]string

		switch dataType {
		case "cdn":
			data = compiled.CDN
		case "waf":
			data = compiled.WAF
		case "cloud":
			data = compiled.Cloud
		default:
			panic(fmt.Sprintf("invalid datatype %s specified", dataType))
		}
		for _, item := range scraper {
			if response, err := item.scraper(http.DefaultClient); err != nil {
				log.Printf("[err] could not scrape %s item: %s\n", item.name, err)
			} else {
				data[item.name] = response
			}
		}
	}
	return compiled, nil
}

// fetchInputItem fetches input items and writes data to map
func (c *Category) fetchInputItem(options *Options, data map[string][]string) error {
	for provider, cidrs := range c.CIDR {
		data[provider] = cidrs
	}
	for provider, urls := range c.URLs {
		for _, item := range urls {
			if cidrs, err := getCIDRFromURL(item); err != nil {
				log.Printf("[err] could not get cidr from %s: %s\n", item, err)
				continue
			} else {
				data[provider] = cidrs
			}
		}
	}
	// Only scrape ASN if we have an ID
	// if !options.HasAuthInfo() {
	// 	// 如果没有验证token，那么就直接结束
	// 	return nil
	// }
	for provider, asn := range c.ASN {
		for _, item := range asn {
			if options.IPInfoToken != "" {
				if cidrs, err := getIpInfoASN(http.DefaultClient, options.IPInfoToken, item); err != nil {
					log.Printf("[ipinfo] could not get asn %s: %s\n", item, err)
					continue
				} else {
					data[provider] = cidrs
				}
			}
			if options.PDCPApiKey != "" {
				if cidrs, err := getAsnMap(item); err != nil {
					log.Printf("[asnmap] could not get asn %s: %s\n", item, err)
					continue
				} else {
					data[provider] = cidrs
				}
			}
			// Add BGP HE.net ASN lookup
			// Assuming there will be a way to specify to use this source,
			// for now, we can add it alongside other ASN lookups or make it conditional if an option is provided.
			// For simplicity, let's assume it's another source to try.
			// A more robust solution would involve a configuration option to select ASN data sources.
			if cidrs, err := getBgpHeASN(http.DefaultClient, item); err != nil {
				log.Printf("[bgp.he.net] could not get asn %s: %s\n", item, err)
				// Potentially continue to next item or provider if this source fails
			} else {
				// Decide how to merge data if multiple ASN sources return results.
				// For now, let's append, but this might lead to duplicates if not handled.
				// A better approach might be to prioritize or use a set-like structure before converting to slice.
				data[provider] = append(data[provider], cidrs...)
				// To avoid duplicates, one might use a map to store unique CIDRs:
				// currentCidrs := make(map[string]struct{})
				//
				//	for _, cidr := range data[provider] {
				//	 currentCidrs[cidr] = struct{}{}
				//	}
				//
				//	for _, newCidr := range cidrs {
				//	 currentCidrs[newCidr] = struct{}{}
				//	}
				//
				// var uniqueCidrs []string
				//
				//	for cidr := range currentCidrs {
				//	 uniqueCidrs = append(uniqueCidrs, cidr)
				//	}
				//
				// data[provider] = uniqueCidrs
			}
		}
	}
	return nil
}

var errNoCidrFound = errors.New("no cidrs found for url")

// getIpInfoASN returns cidrs for an ASN from ipinfo using a token
func getIpInfoASN(httpClient *http.Client, token string, asn string) ([]string, error) {
	if token == "" {
		return nil, errors.New("ipinfo auth token not specified")
	}
	ipinfoClient := ipinfo.NewClient(httpClient, nil, token)
	info, err := ipinfoClient.GetASNDetails(asn)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, errNoCidrFound
	}
	var cidrs []string
	for _, prefix := range info.Prefixes {
		cidrs = append(cidrs, prefix.Netblock)
	}
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// getBgpHeASN returns cidrs for an ASN from bgp.he.net
func getBgpHeASN(httpClient *http.Client, asn string) ([]string, error) {
	asn = strings.TrimPrefix(asn, "AS")
	httpClient.Timeout = 15 * time.Second // Set a timeout for the HTTP client
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(2 * time.Second) // Wait for 2 seconds before retrying
		}
		url := fmt.Sprintf("https://bgp.he.net/super-lg/report/api/v1/prefixes/originated/%s", asn)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create request for bgp.he.net (attempt %d): %w", attempt+1, err)
			continue
		}
		// Set headers as specified in the task
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to get data from bgp.he.net for ASN %s (attempt %d): %w", asn, attempt+1, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body) // Read body for error context
			resp.Body.Close()                     // Close body after reading
			lastErr = fmt.Errorf("bgp.he.net API request failed for ASN %s with status %d (attempt %d): %s", asn, resp.StatusCode, attempt+1, string(bodyBytes))
			continue
		}

		var bgpResp BGPResp
		if err := json.NewDecoder(resp.Body).Decode(&bgpResp); err != nil {
			resp.Body.Close() // Close body in case of decoding error
			lastErr = fmt.Errorf("failed to decode bgp.he.net response for ASN %s (attempt %d): %w", asn, attempt+1, err)
			continue
		}
		resp.Body.Close() // Ensure body is closed

		if len(bgpResp.Prefixes) == 0 {
			return nil, errNoCidrFound // No need to retry if no prefixes found and request was successful
		}

		var cidrs []string
		for _, prefix := range bgpResp.Prefixes {
			cidrs = append(cidrs, prefix.Prefix)
		}
		return cidrs, nil // Success
	}
	return nil, lastErr // All attempts failed
}

// getCIDRFromURL scrapes CIDR ranges for a URL using a regex
func getCIDRFromURL(URL string) ([]string, error) {
	retried := false
retry:
	req, err := http.NewRequest(http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// if the body type is HTML, retry with the first json link in the page (special case for Azure download page to find changing URLs)
	if resp.Header.Get("Content-Type") == "text/html" && !retried {
		var extractedURL string
		docReader, err := goquery.NewDocumentFromReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		docReader.Find("a").Each(func(i int, item *goquery.Selection) {
			src, ok := item.Attr("href")
			if ok && stringsutil.ContainsAny(src, "ServiceTags_Public_") && extractedURL == "" {
				extractedURL = src
			}
		})
		URL = extractedURL
		retried = true
		goto retry
	}

	body := string(data)

	cidrs := cidrRegex.FindAllString(body, -1)
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}

// getAsnMap returns a map of ASN to CIDR ranges
func getAsnMap(asn string) (cidrs []string, err error) {
	client, err := asnmap.NewClient()

	if err != nil {
		return nil, err
	}
	responses, err := client.GetData(asn)
	if err != nil {
		return nil, err
	}
	results, err := asnmap.MapToResults(responses)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errNoCidrFound
	}
	for _, result := range results {
		cidrs = append(cidrs, result.AS_range...)
	}
	if len(cidrs) == 0 {
		return nil, errNoCidrFound
	}
	return cidrs, nil
}
