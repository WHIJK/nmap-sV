package core

import (
	"fmt"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/util"
	"io"
	"net"
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
}

/*
NmapSv
@Description:  处理优先级，并进行扫描
@param address
@param nmapStructs
@return *model.BannerResult
*/
func (sv *NmapSdk) NmapSv(address string, nmapStructs []model.NmapStruct) {
	port := strings.Split(address, ":")[1]
	total := len(nmapStructs)
	for i := 0; i < len(nmapStructs); i++ {
		if nmapStructs[i].Protocol != "UDP" { // 跳过UDP
			if util.StrInSlice(port, util.PortHandle(nmapStructs[i].Ports)) || i >= total { // 判断是否处于常用端口
				if sv.BannerResult, sv.IsMatch = send(address, nmapStructs[i].Probestring, nmapStructs[i].Matches, sv.Timeout); sv.IsMatch == "open" || sv.IsMatch == "closed" {
					break
				}
			} else {
				nmapStructs = append(nmapStructs, nmapStructs[i])
			}
		}
	}
}

/*
send
@Description: 发送数据并进行匹配
@param address
@param probes
@param matches
@return *model.BannerResult
@return string
*/
func send(address, probes string, matches []model.Matches, timeout int) (*model.BannerResult, string) {
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
	var matchFlag bool // 是否成功匹配指纹标志位

	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(timeout))
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
		if probes != "" {
			// 替换，否则会出现规则匹配问题
			probes = strings.ReplaceAll(probes, "\\r\\n", "\r\n")
			io.WriteString(conn, util.HexToString(probes))
		}
		length, err_read := conn.Read(buf)
		if err_read == nil && length > 0 {
			bannerPrint = string(buf[:length]) // 获得指纹信息
			bannerResult.Banner.BannerPrint = strings.Trim(fmt.Sprintf("%#v", bannerPrint), `\"`)
			var pattern string
			var matchArr []string

			for _, match := range matches {
				if match.PatternFlag != "" {
					pattern = util.BufferJoin([]string{"(?", match.PatternFlag, ")", match.Pattern})
				} else {
					pattern = match.Pattern
				}
				matchArr, matchFlag = MatchFingerprint(util.ConvResponse(bannerPrint), pattern)
				if matchFlag { // 匹配到json文件中的正则
					bannerResult.Service = match.Name
					bannerResult.Banner.Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
					bannerResult.Banner.Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
					bannerResult.Banner.Version = MatchGroup(match.Versioninfo.Version, matchArr)
					return bannerResult, "open"
				}
			}
		}
	} else {
		fmt.Println(address, " Timeout")
		return bannerResult, "closed"
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
func (sv *NmapSdk) AddPattern(probestring string, ports []string, nmapStructs *[]model.NmapStruct, probename, pattern, name, pattern_flag, cpename, devicetype, hostname, info, operatingsystem, vendorproductname, version string) {
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
		Versioninfo: Versioninfo{
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
			// 如果probestring，则会添加探针，并且匹配probename相同的matches
			if probestring != "" {
				var pro = &model.NmapStruct{
					Protocol:    "TCP",
					Probename:   probename,
					Ports:       ports,
					Probestring: probestring,
					Matches:     (*nmapStructs)[i].Matches,
				}
				*nmapStructs = append(*nmapStructs, *pro)
			}
			break
		}
	}
}
