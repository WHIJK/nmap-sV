package core

import (
	"encoding/json"
	"goPortBanner/model"
)

/*
@Author: OvO
@Date: 2023/11/1 20:11
*/

func Run(address string, nmapStruct []model.NmapStruct, bannerChannel chan string) {
	banner, isMatch := nmapSv(address, nmapStruct)
	if isMatch != "closed" {
		a, _ := json.Marshal(banner)
		bannerChannel <- string(a)
	}
}
