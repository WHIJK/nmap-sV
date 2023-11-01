package model

/*
@Author: OvO
@Date: 2023/11/1 17:30
*/
type NmapStruct struct {
	Protocol     string   `json:"protocol"`
	Probename    string   `json:"probename"`
	Probestring  string   `json:"probestring"`
	Ports        []string `json:"ports"`
	Sslports     []string `json:"sslports"`
	Totalwaitms  string   `json:"totalwaitms"`
	Tcpwrappedms string   `json:"tcpwrappedms"`
	Rarity       string   `json:"rarity"`
	Fallback     string   `json:"fallback"`
	Matches      []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"matches"`
	Softmatches []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"softmatches"`
}

// 发送的json文件
type DataStrut struct {
	Name string   `json:"name"`
	Data string   `json:"data"`
	Port []string `json:"port"`
}

// 结果struct
type BannerResult struct {
	Address string `json:"address"`
	Service string `json:""`
	Banner  struct {
		Operatingsystem   string `json:"operatingsystem"`
		Vendorproductname string `json:"vendorproductname"`
		Version           string `json:"version"`
		BannerPrint       string `json:"bannerPrint"`
	}
}
