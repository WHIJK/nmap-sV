package core

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/WHIJK/nmap-sV/core/embed"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/script"
	"github.com/WHIJK/nmap-sV/core/util"
	"github.com/miekg/dns"
	"github.com/projectdiscovery/gologger"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

/*
@Author: OvO
@Date: 2023/11/1 17:37
*/

const (
	Open       = "open"
	NotMatched = "not matched"
	Closed     = "closed"
	SoftMatch  = "soft-matched" // 软匹配
)

type NmapSdk struct {
	BannerResult model.BannerResult
	IsMatch      string // 匹配状态,open==开放并且匹配成功，not matched==开放但是未匹配成功,soft-matched 开放但是非精准匹配
	Protocol     string // tcp | udp
	Timeout      int
}

var nmapStructs []model.NmapStruct

func init() {
	nmapStructs = embed.Load()
}

// 定义一个接口类型，用来描述所有脚本函数

// setProtocol 设置协议类型
func (sv *NmapSdk) setProtocol(address, scanType string) {
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
}

/*
NmapSv
@Description:  通过Goroutine分割处理需要发送的探针与对一个匹配的规则
@receiver sv
@param address
@param jobSingle  每个goroutine需要处理多少任务，越大，则goroutine越少
@param scanType 扫描类型
*/
func (sv *NmapSdk) NmapSv(address string, jobSingle int, scanType string, enableScript bool) {
	// 设置协议
	sv.setProtocol(address, scanType)

	if !strings.Contains(address, ":") {
		gologger.Error().Msgf("Invalid host format: %s. The address should include a port, e.g. 'host:port'.", address)
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

	// 划分任务，计算worker使用量
	worker := int(math.Ceil(float64(len(nmapStructs)) / float64(jobSingle)))
	if worker > len(nmapStructs) {
		worker = len(nmapStructs)
	}
	var wg sync.WaitGroup
	var ctx, cancel = context.WithCancel(context.Background())
	resultChan := make(chan NmapSdk, 2048)

	// 启动多个 Goroutines 处理任务
	wg.Add(worker)
	for i := 0; i < worker; i++ {
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
	for {
		select {
		case result, ok := <-resultChan:
			if !ok { // 通道数据为空，并且已经关闭
				if result.BannerResult.Banner.BannerPrint != "" { // 响应内容不为空
					tempResponseBody = result.BannerResult.Banner.BannerPrint
				}
				// 如果UDP没有匹配，确保在所有工作完成后发送 NotMatched 结果
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
				return
			}
			switch result.IsMatch {
			case Closed:
				cancel()
				gologger.Error().Msg(address + " Timeout")
				sv.BannerResult = result.BannerResult
				sv.IsMatch = result.IsMatch
				return
			case SoftMatch:
				sv.BannerResult = result.BannerResult
				sv.IsMatch = result.IsMatch
				if sv.Protocol == "udp" {
					gologger.Info().Msgf("address %s %s is udp", address, sv.BannerResult.Service)
				}
			case Open:
				cancel()

				sv.BannerResult = result.BannerResult
				sv.IsMatch = result.IsMatch
				if enableScript {
					// 检查服务名是否在 Scripts 映射中
					if script, exists := script.Scripts[strings.ToLower(result.BannerResult.Service)]; exists {
						sv.BannerResult.Banner.Extra = script.RunScripts(address)
					}
				}

				if sv.Protocol == "udp" {
					gologger.Info().Msgf("address %s %s is udp", address, sv.BannerResult.Service)
				}
				return
			default:
				if result.BannerResult.Banner.BannerPrint != "" { // 响应内容不为空
					tempResponseBody = result.BannerResult.Banner.BannerPrint
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
		case <-ctx.Done():
			return
		}
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
	for {
		// 处理一次扫描，直到没有剩余端口需要处理
		for _, nmapStruct := range iNmapStructs {
			select {
			case <-ctx.Done():
				return // 如果接收到取消信号，立即退出
			default:
				// 确保当前协议匹配
				if strings.ToLower(nmapStruct.Protocol) == sv.Protocol || sv.Protocol == "" {
					// 优先处理目标端口
					if sliceutil.Contains(util.PortHandle(nmapStruct.Ports), port) || twice >= 1 {
						// 解析超时配置
						if nmapStruct.Totalwaitms != "" {
							timeoutTemp, err := strconv.Atoi(nmapStruct.Totalwaitms)
							if err == nil {
								sv.Timeout = timeoutTemp / 1000
							}
						}

						// 发送探针并处理匹配结果
						result := sv.send(strings.ToLower(nmapStruct.Protocol), address, nmapStruct.Probename, nmapStruct.Probestring, nmapStruct.Matches, nmapStruct.Softmatches)
						if result.IsMatch == Open || result.IsMatch == Closed {
							ctx.Done() // 发送取消信号
							resultChan <- result
							return
						} else if result.IsMatch == SoftMatch {
							resultChan <- result
						}
					} else {
						// 如果是非优先端口，保存未处理的nmapStruct
						tempNmapStructs = append(tempNmapStructs, nmapStruct)
					}
				}
			}
		}

		// 如果当前没有剩余的端口需要处理，结束循环
		if len(tempNmapStructs) == 0 || sv.Protocol == "udp" {
			break
		}

		// 更新nmapStructs，继续处理剩余的端口
		iNmapStructs = tempNmapStructs
		tempNmapStructs = nil // 清空临时存储的未处理端口
		twice++               // 如果不为udp，则开启第二轮扫描
	}

}

/*
send
@Description: 发送数据并进行匹配
@param address
@param probes 探针
@param matches
@param softMatches 软匹配，只有当matches匹配不成功时才会进行
@return *model.BannerResult
@return string
*/
func (sv *NmapSdk) send(protocol, address, probename, probes string, matches, softMatches []model.Matches) NmapSdk {
	// 初始化默认返回结果
	result := NmapSdk{
		IsMatch: NotMatched,
		BannerResult: model.BannerResult{
			Address: address,
			Service: "Unknown",
			Banner:  model.Banner{},
		},
		Protocol: sv.Protocol,
	}

	// 协议过滤
	if sv.Protocol != "" && sv.Protocol != protocol {
		return result
	}
	if stringsutil.ContainsAnyI(probename, "GetRequest") { // http发包代替
		return handleHTTPProbe(address, matches, softMatches, result, probes)
	} else {
		// 初始化缓冲区池
		var bufferPool = sync.Pool{
			New: func() interface{} {
				return make([]byte, 4096)
			},
		}

		// 建立网络连接
		conn, err := net.DialTimeout(protocol, address, time.Second*time.Duration(sv.Timeout))
		if err != nil {
			// 非UDP协议返回Closed状态
			if sv.Protocol != "udp" {
				result.IsMatch = Closed
			}
			return result
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second * time.Duration(sv.Timeout)))

		// 发送探针数据
		if probes != "" {
			probes = strings.ReplaceAll(probes, "\\r\\n", "\r\n")
			_, _ = io.WriteString(conn, util.HexToString(probes))
		}

		// 读取响应数据
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		length, err := conn.Read(buf)
		if err == nil && length > 0 {
			response := string(buf[:length])
			return matchResponseWithFallback(matches, softMatches, result, response, probes)
		}
	}

	// 特殊探针处理（HTTP）
	// if length == 0 && stringsutil.ContainsAnyI(probename, "GetRequest", "HTTPOptions") {
	// 	return handleHTTPProbe(address, matches, softMatches, result, probes)
	// }

	return result
}

// handleHTTPProbe 处理 HTTP 探针逻辑
func handleHTTPProbe(address string, matches, softMatches []model.Matches, result NmapSdk, probes string) NmapSdk {
	var url string
	if strings.HasSuffix(address, ":443") {
		url = "https://" + strings.Split(address, ":")[0]
	} else {
		url = "http://" + address
	}
	status, resp := util.GetHttpBanner(url, result.Timeout)
	if status {
		return matchResponseWithFallback(matches, softMatches, result, resp, probes)
	}
	return result
}

// matchResponseWithFallback 匹配响应并处理软匹配
func matchResponseWithFallback(matches, softMatches []model.Matches, result NmapSdk, response, probes string) NmapSdk {
	tempResult := matchResponse(matches, result, response, probes, false)
	if tempResult.IsMatch == Open {
		return tempResult
	}
	return matchResponse(softMatches, tempResult, response, probes, true)
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
func matchResponse(matches []model.Matches, result NmapSdk, response, probes string, isSoftMatch bool) NmapSdk {
	result.BannerResult.Banner.BannerPrint = strings.Trim(fmt.Sprintf("%#v", response), `"`)

	for _, match := range matches {
		matchArr, matchFlag := MatchFingerprint(util.ConvResponse(response), match.Pattern, match.PatternFlag)
		if !matchFlag {
			continue
		}

		result.BannerResult.ProbeString = probes
		result.BannerResult.Pattern = fmt.Sprintf("%v", match.Pattern)
		result.BannerResult.Banner.Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
		result.BannerResult.Banner.Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
		result.BannerResult.Banner.Version = MatchGroup(match.Versioninfo.Version, matchArr)
		result.IsMatch = SoftMatch
		if !isSoftMatch {
			result.IsMatch = Open
		}

		// 服务映射表替代硬编码
		serviceMap := map[string]string{
			"ms-wbt-server": "rdp",
			"microsoft-ds":  "smb",
			"oracle-tns":    "oracle",
			"ms-sql-s":      "mssql",
			"netbios-ssn":   "netbios",
			"msrpc":         "rpc",
		}
		if service, exists := serviceMap[match.Name]; exists {
			result.BannerResult.Service = service
		} else {
			result.BannerResult.Service = match.Name
		}

		return result
	}

	return result
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
