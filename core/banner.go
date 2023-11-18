package core

import (
	"fmt"
	"github.com/WHIJK/nmap-sV/core/embed"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/util"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

/*
@Author: OvO
@Date: 2023/11/1 17:37
*/

const (
	Open       = "open"
	NotMatched = "not matched"
	Closed     = "closed"
)

type NmapSdk struct {
	BannerResult *model.BannerResult
	IsMatch      string // 匹配状态,open==开放并且匹配成功，not matched==开放但是未匹配成功
	Protocol     string // tcp | udp
	Timeout      int
	NmapStructs  []model.NmapStruct
}

func init() {
	sdk.NmapStructs = embed.Load()
}

/*
NmapSv
@Description:  处理优先级，并进行扫描
@param address
@param nmapStructs
@return *model.BannerResult
*/
func (sv *NmapSdk) NmapSv(address string) {
	if sv.Timeout == 0 {
		sv.Timeout = 5
	}
	if sv.IsMatch = DnsScan(address, sv.Timeout); sv.IsMatch == Open {
		sv.BannerResult = &model.BannerResult{
			Address: address,
			Service: "DNS",
			Banner: model.Banner{
				Operatingsystem:   "",
				Vendorproductname: "",
				Version:           "",
				BannerPrint:       "",
			},
		}
		return
	}
	// 添加规则匹配
	sv.AddPattern(&sdk.NmapStructs, "GetRequest", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sv.AddPattern(&sdk.NmapStructs, "HTTPOptions", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sv.AddPattern(&sdk.NmapStructs, "TerminalServerCookie", "^\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02.*\\x02\\x00\\x00\\x00",
		"ms-wbt-server", "", "o:microsoft:windows", "", "", "", "Windows", "Microsoft Terminal Services",
		"Windows 7 or Server 2008 R2")

	port := strings.Split(address, ":")[1]
	total := len(sdk.NmapStructs)
	for i := 0; i < len(sdk.NmapStructs); i++ {
		// 优先级别端口未匹配成功，跳出并修改状态为关闭，因为端口有可能是端口关闭，避免全部扫描
		if i >= total && sv.Protocol == "udp" && sv.IsMatch == NotMatched {
			sv.IsMatch = Closed
			break
		}
		// 	协议匹配	   &&  (i >= total 未优先级探针匹配 ||  优先端口探测)
		if (strings.ToLower(sdk.NmapStructs[i].Protocol) == sv.Protocol || sv.Protocol == "") && (i >= total || sliceutil.Contains(util.PortHandle(sdk.NmapStructs[i].Ports), port)) {
			//等待时间
			if sdk.NmapStructs[i].Totalwaitms != "" {
				timeoutTemp, err := strconv.Atoi(sdk.NmapStructs[i].Totalwaitms)
				if err == nil {
					sv.Timeout = timeoutTemp / 1000
				}
			}
			if sv.BannerResult, sv.IsMatch = sv.send(strings.ToLower(sdk.NmapStructs[i].Protocol), address, sdk.NmapStructs[i].Probename, sdk.NmapStructs[i].Probestring, append(sdk.NmapStructs[i].Matches, sdk.NmapStructs[i].Softmatches...)); sv.IsMatch == Open || sv.IsMatch == Closed {
				break
			}
		} else {
			// 未优先的放置最后
			sdk.NmapStructs = append(sdk.NmapStructs, sdk.NmapStructs[i])
		}
	}
}

/*
send
@Description: 发送数据并进行匹配
@param address
@param probes 探针
@param matches
@return *model.BannerResult
@return string
*/
func (sv *NmapSdk) send(protocol, address, probename, probes string, matches []model.Matches) (*model.BannerResult, string) {
	var buf = make([]byte, 2048)
	var bannerPrint string // 记录端口的banner信息
	var bannerResult = &model.BannerResult{
		Address: address,
		Service: "Unknown",
		Banner: model.Banner{
			Operatingsystem:   "",
			Vendorproductname: "",
			Version:           "",
			BannerPrint:       "",
		},
	} // banner结果存储
	conn, err := net.DialTimeout(protocol, address, time.Second*time.Duration(sv.Timeout))
	if err == nil {
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(sv.Timeout)))
		defer conn.Close()
		if probes != "" {
			probes = strings.ReplaceAll(probes, "\\r\\n", "\r\n")
			io.WriteString(conn, fmt.Sprintf("%s", util.HexToString(probes)))
		}
		length, err_read := conn.Read(buf)
		if err_read == nil && length > 0 {
			sv.Protocol = protocol             // 获取到响应结果，则协议判断正确
			bannerPrint = string(buf[:length]) // 获得指纹信息
			return matchResponse(matches, bannerResult, bannerPrint, probes)
		} else if length == 0 && stringsutil.ContainsAnyI(probename, "GetRequest", "HTTPOptions") { // 当是这两个探针时，发送后没有数据，则会发送HTTP请求进行探测匹配
			url := "http://" + address
			if hosts := stringsutil.SplitAny(address, ":"); hosts[1] == "80" {
				url = "http://" + hosts[0]
			}
			status, resp := util.GetHttpBanner(url, sv.Timeout)
			if status {
				return matchResponse(matches, bannerResult, resp, probes)
			}
		}
		//tcp端口发送了udp数据，会直接超时，判断一下是否为tcp端口
	} else if sv.Protocol == "" && protocol == "udp" && isTCPPortOpen(address, sv.Timeout) {
		sv.Protocol = "tcp"
		return bannerResult, NotMatched
	} else if sv.Protocol == "" && protocol == "tcp" && stringsutil.ContainsAny(err.Error(), "refused") { // udp端口发送了tcp数据可能报错，connectex: No connection could be made because the target machine actively refused it.
		sv.Protocol = "udp" // 也有可能是端口关闭了
		return bannerResult, NotMatched
	} else if protocol == "udp" {

	} else {
		gologger.Error().Msg(address + " Timeout")
		return bannerResult, Closed
	}
	return bannerResult, NotMatched
}

/*
matchResponse
@Description:  响应匹配
@param matches
@param bannerResult
@param bannerPrint
@param probes
@return *model.BannerResult
@return string
*/
func matchResponse(matches []model.Matches, bannerResult *model.BannerResult, bannerPrint, probes string) (*model.BannerResult, string) {
	var matchFlag bool // 是否成功匹配指纹标志位
	var matchArr []string
	bannerResult.Banner.BannerPrint = strings.Trim(fmt.Sprintf("%#v", bannerPrint), `"`)
	for _, match := range matches {
		matchArr, matchFlag = MatchFingerprint(util.ConvResponse(bannerPrint), match.Pattern, match.PatternFlag)
		if matchFlag { // 匹配到json文件中的正则
			var service string
			switch match.Name {
			case "ms-wbt-server":
				service = "rdp"
			case "microsoft-ds":
				service = "smb"
			case "oracle-tns":
				service = "oracle"
			case "ms-sql-s":
				service = "mssql"
			case "netbios-ssn":
				service = "netbios"
			case "msrpc":
				service = "rpc"
			default:
				service = match.Name
			}
			bannerResult.Service = service
			bannerResult.ProbeString = probes
			bannerResult.Pattern = fmt.Sprintf("%v", match.Pattern)
			bannerResult.Banner.Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
			bannerResult.Banner.Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
			bannerResult.Banner.Version = MatchGroup(match.Versioninfo.Version, matchArr)
			return bannerResult, Open
		}
	}
	return bannerResult, NotMatched
}

/*
AddPattern
@Description: 添加规则
@param probename  在指定的probename添加规则
@param pattern
@param name
@param pattern_flag
@param cpename
@param devicetype
@param hostname
@param info
@param operatingsystem
@param vendorproductname
@param version
@return model.Matches
*/
func (sv *NmapSdk) AddPattern(nmapStructs *[]model.NmapStruct, probename, pattern, name, pattern_flag, cpename, devicetype, hostname, info, operatingsystem, vendorproductname, version string) {
	type Versioninfo struct {
		Cpename           string `json:"cpename"`
		Devicetype        string `json:"devicetype"`
		Hostname          string `json:"hostname"`
		Info              string `json:"info"`
		Operatingsystem   string `json:"operatingsystem"`
		Vendorproductname string `json:"vendorproductname"`
		Version           string `json:"version"`
	}
	var Matches = model.Matches{
		Pattern:     strings.ReplaceAll(pattern, `\x00`, `\0`),
		Name:        name,
		PatternFlag: pattern_flag,
		Versioninfo: model.Versioninfo{
			Cpename:           cpename,
			Devicetype:        devicetype,
			Hostname:          hostname,
			Info:              info,
			Operatingsystem:   operatingsystem,
			Vendorproductname: vendorproductname,
			Version:           version,
		},
	}
	for i, nmapStruct := range *nmapStructs {
		if nmapStruct.Probename == probename {
			(*nmapStructs)[i].Matches = append(nmapStruct.Matches, Matches)
			break
		}
	}
}

/*
DnsScan
@Description: Dns指纹扫描
@param address
@return string
*/
func DnsScan(address string, timeout int) string {
	if addressSlice := stringsutil.SplitAny(address, ":"); len(addressSlice) == 2 && addressSlice[1] == "53" {
		c := dns.Client{
			Timeout: time.Duration(timeout) * time.Second,
		}
		m := dns.Msg{}
		// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
		m.SetQuestion("www.baidu.com.", dns.TypeA)
		_, _, err := c.Exchange(&m, address)
		if err != nil {
			return Closed
		}
		return Open
	}
	return ""
}

/*
isTCPPortOpen
@Description: 判断是否为tcp端口
@param address
@param timeout
@return bool
*/
func isTCPPortOpen(address string, timeout int) bool {
	testTCP, err := net.DialTimeout("tcp", address, time.Duration(timeout)*time.Second)
	if err != nil {
		return false
	}
	defer testTCP.Close()
	return true
}
