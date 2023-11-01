package core

import (
	"encoding/json"
	"fmt"
	"goPortBanner/model"
	"goPortBanner/option"
	"io"
	"net"
	"strings"
	"time"
)

/*
@Author: OvO
@Date: 2023/11/1 17:37
*/

// 请求获取Banner
func GetBanner(address string, nmapStructs []model.NmapStruct) {
	buf := make([]byte, 2048)
	var bannerResult model.BannerResult // banner结果存储
	var matchFlag bool                  // 是否成功匹配指纹标志位

	Service := ""
	Operatingsystem := ""
	Vendorproductname := ""
	Version := ""
	i := 0 // 发送data顺序
start:
	conn, err := net.DialTimeout("tcp", address, time.Second*time.Duration(*option.Timeout)) // 端口扫描
	if err == nil {
		dataList := getNeedFromSendData(strings.Split(address, ":")[1], dataStruts)
		defer conn.Close()
		var result string      // 转化为字符串后的结果
		var bannerPrint string // 记录端口的banner信息
		conn.SetDeadline(time.Now().Add(time.Second * 5))
		io.WriteString(conn, hexToString(dataList[i]))
		length, err_read := conn.Read(buf)

		if err_read == nil && length > 0 {
			bannerPrint = string(buf[:length]) // 获得指纹信息
			for i := 0; i < len(nmapStructs); i++ {
				if nmapStructs[i].Protocol != "UDP" {
					for _, match := range nmapStructs[i].Matches {
						var pattern string
						var matchArr []string //
						// 设置匹配标志位
						if match.PatternFlag != "" {
							pattern = bufferJoin([]string{"(?", match.PatternFlag, ")", match.Pattern})
						} else {
							pattern = match.Pattern
						}
						matchArr, matchFlag = MatchFingerprint(convResponse(bannerPrint), pattern)
						if matchFlag { // 匹配到json文件中的正则
							Service = match.Name
							Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
							Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
							Version = MatchGroup(match.Versioninfo.Version, matchArr)
							goto endone // 获取了匹配结果，跳转写入通道
						}
					}
				}
			}

		} else if length == 0 && i < len(dataList)-1 { //重新发送数据，找指纹
			i++
			goto start
		}
		if !matchFlag {
			// 未获取正则或者返回内容，但端口开放，则设定默认值
			Service = "Unknown"
			Operatingsystem = ""
			Vendorproductname = ""
			Version = ""

		}
	endone: // 写入通道
		cc := strings.Trim(fmt.Sprintf("%#v", string(bannerPrint)), `\"`)
		bannerResult = BannerResult{
			Address: address,
			Service: Service,
			Banner: struct {
				Operatingsystem   string `json:"operatingsystem"`
				Vendorproductname string `json:"vendorproductname"`
				Version           string `json:"version"`
				BannerPrint       string `json:"bannerPrint"`
			}{
				Operatingsystem:   Operatingsystem,
				Vendorproductname: Vendorproductname,
				Version:           Version,
				BannerPrint:       cc,
			},
		}
		a, _ := json.Marshal(bannerResult)
		result = string(a)
		bannerChannel <- result
	} else {
		fmt.Println(address, " Timeout")
	}
}
