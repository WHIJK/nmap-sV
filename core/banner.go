package core

import (
	"fmt"
	"github.com/WHIJK/nmap-sV/core/embed"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/util"
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

type NmapSdk struct {
	BannerResult *model.BannerResult
	IsMatch      string // 匹配状态,open==开放并且匹配成功，not matched==开放但是未匹配成功
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
		if sdk.NmapStructs[i].Protocol != "UDP" { // 跳过UDP
			if i >= total || sdk.NmapStructs[i].Probestring == "" || sliceutil.Contains(util.PortHandle(sdk.NmapStructs[i].Ports), port) { // 探针为空，处于优先端口将优先探测
				//等待时间
				timeout := sv.Timeout
				if sdk.NmapStructs[i].Totalwaitms != "" {
					timeoutTemp, err := strconv.Atoi(sdk.NmapStructs[i].Totalwaitms)
					if err != nil {
						timeoutTemp = sv.Timeout
					}
					timeout = timeoutTemp / 1000
				}
				if sv.BannerResult, sv.IsMatch = send(address, sdk.NmapStructs[i].Probename, sdk.NmapStructs[i].Probestring, append(sdk.NmapStructs[i].Matches, sdk.NmapStructs[i].Softmatches...), timeout); sv.IsMatch == "open" || sv.IsMatch == "closed" {
					break
				}
			} else {
				sdk.NmapStructs = append(sdk.NmapStructs, sdk.NmapStructs[i])
			}
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
func send(address, probename, probes string, matches []model.Matches, timeout int) (*model.BannerResult, string) {
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
	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(timeout))
	if err == nil {
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		defer conn.Close()
		if probes != "" {
			probes = strings.ReplaceAll(probes, "\\r\\n", "\r\n")
			io.WriteString(conn, fmt.Sprintf("%s\n", util.HexToString(probes)))
		}
		length, err_read := conn.Read(buf)
		if err_read == nil && length > 0 {
			bannerPrint = string(buf[:length]) // 获得指纹信息
			return matchResponse(matches, bannerResult, bannerPrint, probes)
		} else if length == 0 && stringsutil.ContainsAnyI(probename, "GetRequest", "HTTPOptions") { // 当是这两个探针时，发送后没有数据，则会发送HTTP请求进行探测匹配
			url := "http://" + address
			if stringsutil.SplitAny(address, ":")[1] == "80" {
				url = "http://" + stringsutil.SplitAny(address, ":")[0]
			}
			status, resp := util.GetHttpBanner(url, timeout)
			if status {
				return matchResponse(matches, bannerResult, resp, probes)
			}
		}
	} else {
		fmt.Println(address, " Timeout")
		return bannerResult, "closed"
	}
	return bannerResult, "not matched"
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
			bannerResult.Service = match.Name
			bannerResult.ProbeString = probes
			bannerResult.Pattern = fmt.Sprintf("%v", match.Pattern)
			bannerResult.Banner.Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
			bannerResult.Banner.Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
			bannerResult.Banner.Version = MatchGroup(match.Versioninfo.Version, matchArr)
			return bannerResult, "open"
		}
	}
	return bannerResult, "not matched"
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
