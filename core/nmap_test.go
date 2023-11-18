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
	sdk2.NmapSv("110.80.180.203:1194")
	//sdk2.NmapSv("110.188.79.63:1194")
	//sdk2.NmapSv("127.0.0.1:445")
	//sdk2.NmapSv("10.2.2.1:53")
	fmt.Println(sdk2.IsMatch)
	fmt.Println(sdk2.Protocol)
	if sdk2.IsMatch != "closed" {
		a, _ := json.Marshal(sdk2.BannerResult)
		fmt.Println(string(a))
	}
}
