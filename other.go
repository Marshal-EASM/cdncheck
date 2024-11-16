package cdncheck

import (
	"regexp"
	"strings"
)

var suffixToSource map[string]string
var regexpToSource map[string]map[*regexp.Regexp]string

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
}

// CheckFQDN checks if fqdns are known cloud ones
func (c *Client) CheckSuffix(fqdns ...string) (isCDN bool, provider string, itemType string, err error) {
	c.Once.Do(func() {
		//suffixToSource = make(map[string]string)
		//for source, suffixes := range generatedData.Common {
		//	for _, suffix := range suffixes {
		//		suffixToSource[suffix] = source
		//	}
		//}

		regexpToSource = make(map[string]map[*regexp.Regexp]string)
		for cnametype, cnamedata := range generatedData.Common {
			regexpToSource[cnametype] = make(map[*regexp.Regexp]string)
			for cnamesource, cnames := range cnamedata {
				for _, cname := range cnames {
					regexpToSource[cnametype][regexp.MustCompile(cname)] = cnamesource
				}
			}
		}
	})

	for _, fqdn := range fqdns {
		for cnametype, cnamedata := range regexpToSource {
			for compiled, source := range cnamedata {
				if compiled.MatchString(fqdn) {
					return true, source, cnametype, nil
				}
			}
		}

		//parsed, err := publicsuffix.Parse(fqdn)
		//if err != nil {
		//	return false, "", "", errors.Wrap(err, "could not parse fqdn")
		//}
		//if discovered, ok := suffixToSource[parsed.TLD]; ok {
		//	return true, discovered, "waf", nil
		//}
		//domain := parsed.SLD + "." + parsed.TLD
		//if discovered, ok := suffixToSource[domain]; ok {
		//	return true, discovered, "waf", nil
		//}
	}

	return false, "", "", nil
}

// CheckWappalyzer checks if the wappalyzer detection are a part of CDN
func (c *Client) CheckWappalyzer(data map[string]struct{}) (isCDN bool, provider string, err error) {
	for technology := range data {
		if strings.Contains(technology, ":") {
			if parts := strings.SplitN(technology, ":", 2); len(parts) == 2 {
				technology = parts[0]
			}
		}
		technology = strings.ToLower(technology)
		if discovered, ok := cdnWappalyzerTechnologies[technology]; ok {
			return true, discovered, nil
		}
	}
	return false, "", nil
}
