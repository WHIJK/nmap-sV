package core

import (
	"fmt"
	"goPortBanner/model"
	"goPortBanner/option"
	"goPortBanner/util"
	"io"
	"net"
	"strings"
	"time"
)

/*
@Author: OvO
@Date: 2023/11/1 17:37
*/

/*
nmapSv
@Description:  处理优先级，并进行扫描
@param address
@param nmapStructs
@return *model.BannerResult
*/
func nmapSv(address string, nmapStructs []model.NmapStruct) (*model.BannerResult, string) {
	port := strings.Split(address, ":")[1]
	var bannerResult *model.BannerResult // banner结果
	var tempStruct []model.NmapStruct    // 未匹配到端口，后续扫描
	var isMatch string                   // 匹配状态,open==开放并且匹配成功，not matched==开放但是未匹配成功
	for _, nmapStruct := range nmapStructs {
		if nmapStruct.Protocol != "UDP" { // 跳过UDP
			if util.StrInSlice(port, util.PortHandle(nmapStruct.Ports)) { // 判断是否处于常用端口
				if bannerResult, isMatch = send(address, nmapStruct.Probestring, nmapStruct.Matches); isMatch == "open" || isMatch == "closed" {
					return bannerResult, isMatch
				}
			} else {
				tempStruct = append(tempStruct, nmapStruct)
			}
			nmapStructs = append(nmapStructs[:len(nmapStructs)-len(tempStruct)], tempStruct...)
		}
	}

	// 发送剩余指纹扫描
	//if isMatch == "not matched" || isMatch == "" {
	//	for _, nmapStruct := range lastStruct {
	//		if bannerResult, isMatch = send(address, nmapStruct.Probestring, nmapStruct.Matches); isMatch == "open" || isMatch == "closed" {
	//			return bannerResult, isMatch
	//		}
	//	}
	//}

	return bannerResult, isMatch
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
func send(address, probes string, matches []model.Matches) (*model.BannerResult, string) {
	// 替换，否则会出现规则匹配问题
	probes = strings.ReplaceAll(probes, "\\r\\n", "\r\n")

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

	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(*option.Timeout))
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second * time.Duration(*option.Timeout)))
		io.WriteString(conn, util.HexToString(probes))
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
