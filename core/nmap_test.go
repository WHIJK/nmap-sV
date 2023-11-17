package core

import (
	"encoding/json"
	"fmt"
	"testing"
)

/*
@Author: OvO
@Date: 2023/11/16 14:36
*/

func TestRunner(t *testing.T) {
	var sdk2 = NmapSdk{}
	sdk2.Timeout = 5
	//sdk2.NmapSv("114.34.125.67:3389")
	sdk2.NmapSv("139.224.12.78:7002")
	fmt.Println(sdk2.IsMatch)
	if sdk2.IsMatch != "closed" {
		a, _ := json.Marshal(sdk2.BannerResult)
		fmt.Println(string(a))
	}
}
