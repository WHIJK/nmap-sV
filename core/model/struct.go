package model

/*
@Author: OvO
@Date: 2023/11/1 17:30
*/

type NmapStruct struct {
	Protocol     string    `json:"protocol"`
	Probename    string    `json:"probename"`
	Probestring  string    `json:"probestring"`
	Ports        []string  `json:"ports"`
	Sslports     []string  `json:"sslports"`
	Totalwaitms  string    `json:"totalwaitms"`
	Tcpwrappedms string    `json:"tcpwrappedms"`
	Rarity       string    `json:"rarity"`
	Fallback     string    `json:"fallback"`
	Matches      []Matches `json:"matches"`
	Softmatches  []Matches `json:"softmatches"`
}
type Versioninfo struct {
	Cpename           string `json:"cpename"`
	Devicetype        string `json:"devicetype"`
	Hostname          string `json:"hostname"`
	Info              string `json:"info"`
	Operatingsystem   string `json:"operatingsystem"`
	Vendorproductname string `json:"vendorproductname"`
	Version           string `json:"version"`
}
type Matches struct {
	Pattern     string      `json:"pattern"`
	Name        string      `json:"name"`
	PatternFlag string      `json:"pattern_flag"`
	Versioninfo Versioninfo `json:"versioninfo"`
}

// 发送的json文件
type DataStrut struct {
	Name string   `json:"name"`
	Data string   `json:"data"`
	Port []string `json:"port"`
}

// 结果struct
type BannerResult struct {
	Address     string `json:"address"`
	Service     string `json:""`
	Banner      Banner
	Pattern     string // 匹配成功规则
	ProbeString string // 探针
}

type Banner struct {
	Operatingsystem   string `json:"operatingsystem"`
	Vendorproductname string `json:"vendorproductname"`
	Version           string `json:"version"`
	BannerPrint       string `json:"bannerPrint"`
}
