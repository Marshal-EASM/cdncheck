package cdncheck

import (
	"net"
	"net/netip"

	"github.com/gaissmai/bart"
)

type AKSKConfig struct {
	// https://console.cloud.tencent.com/cam/capi
	TencentId  string `yaml:"TencentId"`
	TencentKey string `yaml:"TencentKey"`

	// https://ram.console.aliyun.com/manage/ak
	AlibabaId  string `yaml:"AlibabaId"`
	AlibabaKey string `yaml:"AlibabaKey"`

	// https://console.bce.baidu.com/iam
	BaiduId  string `yaml:"BaiduId"`
	BaiduKey string `yaml:"BaiduKey"`

	// https://console.volcengine.com/iam/keymanage/
	VolcengineId  string `yaml:"VolcengineId"`
	VolcengineKey string `yaml:"VolcengineKey"`

	// https://support.huaweicloud.com/devg-apisign/api-sign-provide-aksk.html
	HuaweiID  string `yaml:"HuaweiID"`
	HuaweiKey string `yaml:"HuaweiKey"`

	// https://support.huaweicloud.com/devg-apisign/api-sign-provide-aksk.html
	WangsuID  string `yaml:"WangsuID"`
	WangsuKey string `yaml:"WangsuKey"`
}

// InputCompiled contains a compiled list of input structure
type InputCompiled struct {
	// CDN contains a list of ranges for CDN cidrs
	CDN map[string][]string `yaml:"cdn,omitempty" json:"cdn,omitempty"`
	// WAF contains a list of ranges for WAF cidrs
	WAF map[string][]string `yaml:"waf,omitempty" json:"waf,omitempty"`
	// Cloud contains a list of ranges for Cloud cidrs
	Cloud map[string][]string `yaml:"cloud,omitempty" json:"cloud,omitempty"`
	// Common contains a list of suffixes for major sources
	Common map[string][]string `yaml:"common,omitempty" json:"common,omitempty"`
}

// providerScraper is a structure for scraping providers
type providerScraper struct {
	rangers map[string]*bart.Table[net.IP]
}

// newProviderScraper returns a new provider scraper instance
func newProviderScraper(ranges map[string][]string) *providerScraper {
	scraper := &providerScraper{rangers: make(map[string]*bart.Table[net.IP])}
	for provider, items := range ranges {
		ranger := new(bart.Table[net.IP])
		for _, cidr := range items {
			if network, err := netip.ParsePrefix(cidr); err == nil {
				ranger.Insert(network, nil)
			}
		}
		scraper.rangers[provider] = ranger
	}
	return scraper
}

// Match returns true if the IP matches provided CIDR ranges
func (p *providerScraper) Match(ip net.IP) (bool, string, error) {
	parsed, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false, "", err
	}

	for provider, ranger := range p.rangers {
		if _, contains := ranger.Lookup(parsed); contains {
			return true, provider, err
		}
	}
	return false, "", nil
}
