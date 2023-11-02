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
var sdk = NmapSdk{}

func init() {
	sdk.AddPattern("", []string{}, &nmapStructs, "TerminalServerCookie", "^\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02.*\\x02\\x00\\x00\\x00",
		"ms-wbt-server", "", "o:microsoft:windows", "", "", "", "Windows", "Microsoft Terminal Services",
		"Windows 7 or Server 2008 R2")
	sdk.AddPattern("", []string{}, &nmapStructs, "GetRequest", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
	sdk.AddPattern("GET / HTTP/1.1\\r\\n\\r\\n", []string{"1", "70", "79", "80-85", "88", "113", "139", "143", "280", "497", "505", "514", "515", "540", "554", "591", "620", "631", "783", "888", "898", "900", "901", "1026", "1080", "1042", "1214", "1220", "1234", "1314", "1344", "1503", "1610", "1611", "1830", "1900", "2001", "2002", "2030", "2064", "2160", "2306", "2396", "2525", "2715", "2869", "3000", "3002", "3052", "3128", "3280", "3372", "3531", "3689", "3872", "4000", "4444", "4567", "4660", "4711", "5000", "5427", "5060", "5222", "5269", "5280", "5432", "5800-5803", "5900", "5985", "6103", "6346", "6544", "6600", "6699", "6969", "7002", "7007", "7070", "7100", "7402", "7776", "8000-8010", "8080-8085", "8088", "8118", "8181", "8530", "8880-8888", "9000", "9001", "9030", "9050", "9080", "9090", "9999", "10000", "10001", "10005", "11371", "13013", "13666", "13722", "14534", "15000", "17988", "18264", "31337", "40193", "50000", "55555"}, &nmapStructs, "GetRequest", "^HTTP/1\\.[1\\|0]",
		"http", "", "", "", "", "", "", "",
		"")
}

func Run(address string, bannerChannel chan string) {
	sdk.Timeout = *option.Timeout
	sdk.NmapSv(address, nmapStructs)
	if sdk.IsMatch != "closed" {
		a, _ := json.Marshal(sdk.BannerResult)
		bannerChannel <- string(a)
	}
}
