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
	sdk2.NmapSv("120.55.203.40:2008", 30)
	//sdk2.HandleByGoRunTine("10.2.2.15:22", 30)
	fmt.Println(sdk2.IsMatch)
	fmt.Println(sdk2.Protocol)
	if sdk2.IsMatch != "closed" {
		a, _ := json.Marshal(sdk2.BannerResult)
		fmt.Println(string(a))
	}
}
