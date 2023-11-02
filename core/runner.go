package core

import (
	"encoding/json"
	"github.com/WHIJK/nmap-sV/core/embed"
	"github.com/WHIJK/nmap-sV/option"
)

/*
@Author: OvO
@Date: 2023/11/1 20:11
*/

var nmapStructs = embed.Load() // 加载文件

func Run(address string, bannerChannel chan string) {
	var sdk = NmapSdk{}
	sdk.Timeout = *option.Timeout
	sdk.AddPattern(&nmapStructs, "TerminalServerCookie", "^\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02.*\\x02\\x00\\x00\\x00",
		"ms-wbt-server", "", "o:microsoft:windows", "", "", "", "Windows", "Microsoft Terminal Services",
		"Windows 7 or Server 2008 R2")
	sdk.AddPattern(&nmapStructs, "GetRequest", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sdk.NmapSv(address, nmapStructs)
	if sdk.IsMatch != "closed" {
		a, _ := json.Marshal(sdk.BannerResult)
		bannerChannel <- string(a)
	}
}
