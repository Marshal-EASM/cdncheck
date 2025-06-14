package cdncheck

import (
	"net"
	"strings"
	"sync"

	"github.com/projectdiscovery/retryabledns"
)

var (
	DefaultCDNProviders   string
	DefaultWafProviders   string
	DefaultCloudProviders string
)

// DefaultResolvers trusted (taken from fastdialer)
var DefaultResolvers = []string{
	"180.76.76.76:53",
	"112.124.47.27:53",
	"1.1.1.1:53",
	"223.5.5.5:53",
	"223.6.6.6:53",
	"114.114.114.114:53",
	"119.29.29.29:53",
}

// Client checks for CDN based IPs which should be excluded
// during scans since they belong to third party firewalls.
type Client struct {
	sync.Once
	cdn          *providerScraper
	waf          *providerScraper
	cloud        *providerScraper
	retriabledns *retryabledns.Client

	// extend
	config *AKSKConfig
}

// New creates cdncheck client with default options
// NewWithOpts should be preferred over this function
func New() *Client {
	_client, _ := NewWithOpts(3, []string{})
	return _client
}

// NewWithOpts creates cdncheck client with custom options
func NewWithOpts(MaxRetries int, resolvers []string) (*Client, error) {
	if MaxRetries <= 0 {
		MaxRetries = 3
	}
	if len(resolvers) == 0 {
		resolvers = DefaultResolvers
	}
	retryabledns, err := retryabledns.New(resolvers, MaxRetries)
	if err != nil {
		return nil, err
	}

	// 读取配置文件
	// akskConfig, err := ReadAKSKConfig("config.yaml")
	// if err != nil {
	//		return nil, err
	//	}

	_client := &Client{
		cdn:          newProviderScraper(generatedData.CDN),
		waf:          newProviderScraper(generatedData.WAF),
		cloud:        newProviderScraper(generatedData.Cloud),
		retriabledns: retryabledns,
		//config:       akskConfig,
	}
	return _client, nil
}

// CheckCDN checks if an IP is contained in the cdn denylist
func (c *Client) CheckCDN(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cdn.Match(ip)
	return matched, value, err
}

// CheckWAF checks if an IP is contained in the waf denylist
func (c *Client) CheckWAF(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.waf.Match(ip)
	return matched, value, err
}

// CheckCloud checks if an IP is contained in the cloud denylist
func (c *Client) CheckCloud(ip net.IP) (matched bool, value string, err error) {
	matched, value, err = c.cloud.Match(ip)
	return matched, value, err
}

// Check checks if ip belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
func (c *Client) Check(ip net.IP) (matched bool, value string, itemType string, err error) {

	// 匹配cdn
	if matched, value, err = c.cdn.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cdn", nil
	}

	// 匹配waf
	if matched, value, err = c.waf.Match(ip); err == nil && matched && value != "" {
		return matched, value, "waf", nil
	}

	// 匹配cloud
	if matched, value, err = c.cloud.Match(ip); err == nil && matched && value != "" {
		return matched, value, "cloud", nil
	}
	return false, "", "", err
}

// Check Domain with fallback checks if domain belongs to one of CDN, WAF and Cloud . It is generic method for Checkxxx methods
// Since input is domain, as a fallback it queries CNAME records and checks if domain is WAF
func (c *Client) CheckDomainWithFallback(domain string) (matched bool, value string, itemType string, err error) {
	dnsData, err := c.retriabledns.Resolve(domain)
	if err != nil {
		return false, "", "", err
	}

	// 判断 dns.TypeA, dns.TypeAAAA 是否 CDN
	matched, value, itemType, err = c.CheckDNSResponse(dnsData)
	if err != nil {
		return false, "", "", err
	}

	// 如果匹配则进行返回
	if matched {
		return matched, value, itemType, nil
	}

	// note: 只获取 dns.TypeCNAME
	dnsData, err = c.retriabledns.CNAME(domain)
	if err != nil {
		return false, "", "", err
	}

	// 判断 dns.TypeCNAME 是否 CDN
	return c.CheckDNSResponse(dnsData)
}

// CheckDNSResponse is same as CheckDomainWithFallback but takes DNS response as input
func (c *Client) CheckDNSResponse(dnsResponse *retryabledns.DNSData) (matched bool, value string, itemType string, err error) {

	// note: 通过DNS A记录来判断是否是CDN
	if dnsResponse.A != nil {
		for _, ip := range dnsResponse.A {
			ipAddr := net.ParseIP(ip)
			if ipAddr == nil {
				continue
			}
			if err != nil {
				return false, "", "", err
			}
			matched, value, itemType, err = c.Check(ipAddr)
			if err != nil {
				return false, "", "", err
			}
			if matched {
				return matched, value, itemType, nil
			}
		}
	}

	// note: 通过DNS CNAME记录来判断是否是CDN
	// 通过检查后缀fqdn来判断
	if dnsResponse.CNAME != nil {
		matched, discovered, itemType, err := c.CheckSuffix(dnsResponse.CNAME...)
		if err != nil {
			return false, "", itemType, err
		}
		if matched {
			// for now checkSuffix only checks for wafs
			return matched, discovered, itemType, nil
		}
	}
	return false, "", "", err
}

func mapKeys(m map[string][]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

//
//// custom implement
//func (c *Client) _checkAliyunCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.AlibabaId == "" || c.config.AlibabaKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	_client, err := ali_cdn20180510.NewClient(&ali_openapi.Config{
//		AccessKeyId:     ali_tea.String(c.config.AlibabaId),
//		AccessKeySecret: ali_tea.String(c.config.AlibabaKey),
//		Endpoint:        ali_tea.String("cdn.aliyuncs.com"),
//	})
//
//	if err != nil {
//		gologger.Debug().Msgf("阿里云客户端初始化出错: %v", err)
//		return false, "", err
//	}
//
//	// todo: 单用户调用频率：50 次/秒。
//	// note: https://api.aliyun.com/api/Cdn/2018-05-10/DescribeIpInfo
//	describeIpInfoRequest, runtime := &ali_cdn20180510.DescribeIpInfoRequest{IP: ali_tea.String(ip)}, &ali_util.RuntimeOptions{}
//	response, err := _client.DescribeIpInfoWithOptions(describeIpInfoRequest, runtime)
//	if err != nil {
//		gologger.Debug().Msgf("阿里云检查CDN出错: %v", err)
//		return false, "", err
//	}
//
//	if response.Body != nil && *response.Body.CdnIp == "True" {
//		return true, "阿里云", nil
//	}
//
//	return false, "", err
//}
//
//func (c *Client) _checkBaiduCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.BaiduId == "" || c.config.BaiduKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	// 初始化客户端
//	_client, err := bd_bce.NewBceClientWithAkSk(c.config.BaiduId, c.config.BaiduKey, "https://cdn.baidubce.com")
//	if err != nil {
//		gologger.Debug().Msgf("百度云客户端初始化出错: %v", err)
//		return false, "", err
//	}
//
//	// 构造请求
//	req := &bd_bce.BceRequest{}
//	// note: https://cloud.baidu.com/doc/CDN/s/8jwvyeunq
//	// note: https://console.bce.baidu.com/support/#/api?product=CDN&project=CDN&parent=IP%E6%9F%A5%E8%AF%A2&api=v2%2Futils&method=get
//	req.SetMethod("GET")
//	req.SetUri("/v2/utils")
//	req.SetHeaders(map[string]string{"Accept": "application/json"})
//	req.SetParams(map[string]string{"action": "describeIp", "ip": ip})
//	payload, _ := bd_bce.NewBodyFromString("")
//	req.SetBody(payload)
//
//	// 获取结果
//	resp := &bd_bce.BceResponse{}
//	err = _client.SendRequest(req, resp)
//	if err != nil {
//		gologger.Debug().Msgf("百度云请求 %s 出错: %v", ip, err)
//		return false, "", err
//	}
//
//	respBody := resp.Body()
//	defer respBody.Close()
//	body, err := ioutil.ReadAll(respBody)
//	if err != nil {
//		gologger.Debug().Msgf("百度云获取数据 %s 出错: %v", ip, err)
//		return false, "", err
//	}
//
//	// 数据解码
//	json, err := gjson.DecodeToJson(string(body))
//	if err != nil {
//		gologger.Debug().Msgf("百度云解码数据 %s 出错: %v", ip, err)
//		return false, "", err
//	}
//
//	// 归属情况
//	if json.Get("cdnIP").String() == "true" {
//		return true, "百度云", err
//	} else {
//		return false, "", err
//	}
//
//}
//
//func (c *Client) _checkHuaweiCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.HuaweiID == "" || c.config.HuaweiKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	// 初始化客户端
//	_auth := global.NewCredentialsBuilder().WithAk(c.config.HuaweiID).WithSk(c.config.HuaweiKey).Build()
//	_client := huawei_cdn.NewCdnClient(huawei_cdn.CdnClientBuilder().WithRegion(huawei_region.ValueOf("cn-north-1")).WithCredential(_auth).Build())
//
//	// 构造请求
//	// note: https://console.huaweicloud.com/apiexplorer/#/openapi/CDN/debug?api=ShowIpInfo&version=v1
//	// note: https://console.huaweicloud.com/apiexplorer/#/openapi/CDN/debug?version=v2&api=ShowIpInfo
//	request := &model.ShowIpInfoRequest{}
//	request.Ips = ip
//	response, err := _client.ShowIpInfo(request)
//	if err != nil {
//		gologger.Debug().Msgf("华为云获取数据 %s 出错: %v", ip, err)
//		return false, "", err
//	}
//
//	if response != nil && response.CdnIps != nil && len(*response.CdnIps) > 0 && *(*response.CdnIps)[0].Belongs {
//		return true, "华为云", nil
//	}
//
//	return false, "", err
//}
//
//func (c *Client) _checkTencentCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.TencentId == "" || c.config.TencentKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	// get a credential
//	credential := tx_common.NewCredential(c.config.TencentId, c.config.TencentKey)
//
//	// get a client, clientProfile is optional
//	cpf := tx_profile.NewClientProfile()
//	cpf.HttpProfile.Endpoint = "cdn.tencentcloudapi.com"
//	_client, err := tx_cdn.NewClient(credential, "", cpf)
//	if err != nil {
//		gologger.Debug().Msgf("腾讯云客户端初始化出错: %v", err)
//		return false, "", err
//	}
//
//	// get a request
//	// note: https://console.cloud.tencent.com/api/explorer?Product=cdn&Version=2018-06-06&Action=DescribeCdnIp
//	request := tx_cdn.NewDescribeCdnIpRequest()
//	request.Ips = tx_common.StringPtrs([]string{ip})
//	response, err := _client.DescribeCdnIp(request)
//
//	// decode
//	if err != nil {
//		gologger.Debug().Msgf("腾讯云检查CDN出错: %v", err)
//		return false, "", err
//	}
//
//	Platform, err := gregex.MatchString(`"Platform":"(.*?)"`, response.ToJsonString())
//	if err != nil {
//		return false, "", err
//	}
//
//	if Platform[1] == "yes" {
//		return true, "腾讯云", nil
//	}
//
//	return false, "", err
//}
//
//func (c *Client) _checkVolcengineCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.VolcengineId == "" || c.config.VolcengineKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	// get a session
//	sess, err := session.NewSession(volcengine.NewConfig().WithRegion("cn-beijing").WithCredentials(
//		credentials.NewStaticCredentials(c.config.VolcengineId, c.config.VolcengineKey, "")))
//	if err != nil {
//		gologger.Debug().Msgf("火山引擎客户端初始化出错: %v", err)
//	}
//	svc := hs_cdn.New(sess)
//
//	// get a input
//	describeCdnIPInput := &hs_cdn.DescribeCdnIPInput{
//		IPs: volcengine.StringSlice([]string{ip}),
//	}
//
//	// is cdn
//	// note: https://api.volcengine.com/api-explorer?action=DescribeCdnIP&groupName=%E8%AF%81%E4%B9%A6%E7%AE%A1%E7%90%86%E7%9B%B8%E5%85%B3%E6%8E%A5%E5%8F%A3&serviceCode=CDN&version=2021-03-01
//	response, err := svc.DescribeCdnIP(describeCdnIPInput)
//	if err != nil {
//		gologger.Debug().Msgf("火山引擎检查CDN出错: %v", err)
//		return false, "", err
//	}
//
//	if len(response.IPs) > 0 && *response.IPs[0].CdnIp {
//		return true, "火山引擎", nil
//	}
//
//	return false, "", err
//
//}
//
//func (c *Client) _checkWangsuCdn(input net.IP) (matched bool, cdn string, err error) {
//	if c.config.WangsuID == "" || c.config.WangsuKey == "" {
//		return false, "", nil
//	}
//
//	ip := input.String()
//
//	// get a request
//	ipInfoServiceRequest := client.IpInfoServiceRequest{}
//	var subipInfoServiceRequest0 = ip
//	ipInfoServiceRequest.SetIp([]*string{&subipInfoServiceRequest0})
//
//	// get client
//	var config auth.AkskConfig
//	config.AccessKey = c.config.WangsuID
//	config.SecretKey = c.config.WangsuKey
//	config.EndPoint = "open.chinanetcenter.com"
//	config.Uri = "/api/tools/ip-info"
//	config.Method = "POST"
//
//	// note: https://apiexplorer.wangsu.com/apiexplorer/sdk?productType=all_product&language=ZH_CN&apiId=3515&rsr=ws
//	response, err := auth.Invoke(config, ipInfoServiceRequest.String())
//	if err != nil {
//		gologger.Debug().Msgf("网宿云检查CDN出错: %v", err)
//		return false, "", err
//	}
//
//	json, err := gjson.DecodeToJson(response)
//	if err != nil {
//		gologger.Debug().Msgf("网宿云解码数据 %s 出错: %v", ip, err)
//		return false, "", err
//	}
//
//	// 归属情况
//	if json.Get("result.0.isCdnIp").Bool() {
//		return true, "网宿云", nil
//	}
//
//	return false, "", err
//}
