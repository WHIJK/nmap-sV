package core

import (
	"context"
	"fmt"
	"github.com/WHIJK/nmap-sV/core/embed"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/util"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
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
	BannerResult model.BannerResult
	IsMatch      string // 匹配状态,open==开放并且匹配成功，not matched==开放但是未匹配成功
	Protocol     string // tcp | udp
	Timeout      int
}

var nmapStructs []model.NmapStruct

func init() {
	nmapStructs = embed.Load()
}

/*
NmapSv
@Description:  通过Goroutine分割处理需要发送的探针与对一个匹配的规则
@receiver sv
@param address
@param jobSingle  每个goroutine需要处理多少任务，越大，则goroutine越少
@param scanType 扫描类型
*/
func (sv *NmapSdk) NmapSv(address string, jobSingle int, scanType string) {
	switch scanType {
	case "tcp":
		sv.Protocol = "tcp"
	case "udp":
		sv.Protocol = "udp"
	default:
		if isTCPPortOpen(address, sv.Timeout) {
			sv.Protocol = "tcp"
		} else {
			sv.Protocol = "udp"
		}
	}

	if !stringsutil.ContainsAny(address, ":") {
		return
	}
	if sv.Timeout == 0 {
		sv.Timeout = 5
	}
	if sv.IsMatch = DnsScan(address, sv.Timeout); sv.IsMatch == Open {
		sv.BannerResult = model.BannerResult{
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
	sv.AddPattern(&nmapStructs, "GetRequest", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sv.AddPattern(&nmapStructs, "HTTPOptions", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sv.AddPattern(&nmapStructs, "TerminalServerCookie", "^\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02.*\\x02\\x00\\x00\\x00",
		"ms-wbt-server", "", "o:microsoft:windows", "", "", "", "Windows", "Microsoft Terminal Services",
		"Windows 7 or Server 2008 R2")

	worker := int(math.Ceil(float64(len(nmapStructs)) / float64(jobSingle)))
	var wg sync.WaitGroup
	var ctx, cancel = context.WithCancel(context.Background())
	resultChan := make(chan NmapSdk, 2048)
	for i := 0; i < worker; i++ {
		wg.Add(1)
		if (i+1)*jobSingle <= len(nmapStructs) {
			go sv.HandleEveryGoRouTine(nmapStructs[i*jobSingle:(i+1)*jobSingle], address, &wg, ctx, resultChan) // 启动多个goroutine，每个处理切片的一部分
		} else {
			go sv.HandleEveryGoRouTine(nmapStructs[(i)*jobSingle:], address, &wg, ctx, resultChan) // 超出长度，则处理至结束
		}
	}
	go func() {
		wg.Wait()
		close(resultChan) // 关闭通道，表示所有goroutine都已经完成
	}()
	// 通过select循环监听通道，取得最先发送的结果
	var tempResponseBody string
	for result := range resultChan {
		switch result.IsMatch {
		case Closed:
			cancel()
			gologger.Error().Msg(address + " Timeout")
			sv.BannerResult = result.BannerResult
			sv.IsMatch = result.IsMatch
			return
		case Open:
			cancel()
			sv.BannerResult = result.BannerResult
			sv.IsMatch = result.IsMatch
			if sv.Protocol == "udp" {
				gologger.Info().Msgf("address %s %s is udp", address, sv.BannerResult.Service)
			}
			return
		default:
			if result.BannerResult.Banner.BannerPrint != "" { // 响应内容不为空
				tempResponseBody = result.BannerResult.Banner.BannerPrint
			}
		}
	}
	sv.BannerResult = model.BannerResult{
		Address: address,
		Service: "Unknown",
		Banner: model.Banner{
			Operatingsystem:   "",
			Vendorproductname: "",
			Version:           "",
			BannerPrint:       tempResponseBody,
		},
	}
	sv.IsMatch = NotMatched
	if sv.Protocol == "udp" && sv.BannerResult.Banner.BannerPrint == "" { // 如果Udp没有response，则直接变成closed状态【udp只匹配优先端口】
		sv.IsMatch = Closed
		gologger.Error().Msg(address + " closed or udp response is nil ")
	}

}

/*
HandleEveryGoRouTine
@Description: 对每一个goroutine的任务进行处理
@receiver sv
@param iNmapStructs
@param address
@param wg
@param ctx
@param resultChan
*/
func (sv *NmapSdk) HandleEveryGoRouTine(iNmapStructs []model.NmapStruct, address string, wg *sync.WaitGroup, ctx context.Context, resultChan chan NmapSdk) {
	defer wg.Done()
	var tempNmapStructs []model.NmapStruct
	// banner结果存储
	port := stringsutil.SplitAny(address, ":")[1]
	twice := 0
AppendScan:
	if twice < 2 {
		twice++
		for _, nmapStruct := range iNmapStructs {
			select {
			case <-ctx.Done():
				return // 如果接收到停止信号，立即返回
			default:
				if strings.ToLower(nmapStruct.Protocol) == sv.Protocol || sv.Protocol == "" {
					//  优先端口探测
					if sliceutil.Contains(util.PortHandle(nmapStruct.Ports), port) || twice >= 2 {
						//等待时间
						if nmapStruct.Totalwaitms != "" {
							timeoutTemp, err := strconv.Atoi(nmapStruct.Totalwaitms)
							if err == nil {
								sv.Timeout = timeoutTemp / 1000
							}
						}
						if result := sv.send(strings.ToLower(nmapStruct.Protocol), address, nmapStruct.Probename, nmapStruct.Probestring, append(nmapStruct.Matches, nmapStruct.Softmatches...)); result.IsMatch == Open || result.IsMatch == Closed {
							ctx.Done()
							resultChan <- result
							return
						}
					} else { // 未探测的则放置第二次
						tempNmapStructs = append(tempNmapStructs, nmapStruct)
					}
				}
			}
		}
	}
	if twice < 2 && sv.Protocol != "udp" { // 如果不为udp，则进行剩余指纹扫描,  udp只扫描常用端口列表内的
		iNmapStructs = tempNmapStructs
		goto AppendScan
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
func (sv *NmapSdk) send(protocol, address, probename, probes string, matches []model.Matches) NmapSdk {
	var tempBannerResult = NmapSdk{
		IsMatch: NotMatched,
		BannerResult: model.BannerResult{
			Address: address,
			Service: "Unknown",
			Banner: model.Banner{
				Operatingsystem:   "",
				Vendorproductname: "",
				Version:           "",
				BannerPrint:       "",
			},
		},
		Protocol: "",
	}
	//如果一个goroutine判断出了协议，这里就会跳过其他协议探针的发送
	if sv.Protocol == "" || sv.Protocol == protocol {
		var buf = make([]byte, 2048)
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
				return matchResponse(matches, tempBannerResult, string(buf[:length]), probes)
			} else if length == 0 && stringsutil.ContainsAnyI(probename, "GetRequest", "HTTPOptions") { // 当是这两个探针时，发送后没有数据，则会发送HTTP请求进行探测匹配
				url := "http://" + address
				if hosts := stringsutil.SplitAny(address, ":"); hosts[1] == "80" {
					url = "http://" + hosts[0]
				}
				status, resp := util.GetHttpBanner(url, sv.Timeout)
				if status {
					return matchResponse(matches, tempBannerResult, resp, probes)
				}
			}
		} else if sv.Protocol != "udp" {
			tempBannerResult.IsMatch = Closed
			return tempBannerResult
		}
	}
	return tempBannerResult
}

/*
matchResponse
@Description:  响应匹配
@param matches
@param bannerPrint
@param probes
@return *model.BannerResult
@return string
*/
func matchResponse(matches []model.Matches, tempNmapSdk NmapSdk, bannerPrint, probes string) NmapSdk {
	var matchFlag bool // 是否成功匹配指纹标志位
	var matchArr []string
	tempNmapSdk.BannerResult.Banner.BannerPrint = strings.Trim(fmt.Sprintf("%#v", bannerPrint), `"`)
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
			tempNmapSdk.BannerResult.Service = service
			tempNmapSdk.BannerResult.ProbeString = probes
			tempNmapSdk.BannerResult.Pattern = fmt.Sprintf("%v", match.Pattern)
			tempNmapSdk.BannerResult.Banner.Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
			tempNmapSdk.BannerResult.Banner.Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
			tempNmapSdk.BannerResult.Banner.Version = MatchGroup(match.Versioninfo.Version, matchArr)
			tempNmapSdk.IsMatch = Open
			return tempNmapSdk
		}
	}
	return tempNmapSdk
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
