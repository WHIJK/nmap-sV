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
	sdk2.Timeout = 10
	sdk2.NmapSv("39.105.2.10:9200")
	fmt.Println(sdk2.IsMatch)
	if sdk2.IsMatch != "closed" {
		a, _ := json.Marshal(sdk2.BannerResult)
		fmt.Println(string(a))
	}
}
