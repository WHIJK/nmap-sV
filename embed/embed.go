package embed

import (
	_ "embed"
	"encoding/json"
	"goPortBanner/model"
)

/*
@Author: OvO
@Date: 2023/11/1 17:31
*/

//go:embed nmap.json
var nmapJson []byte

// 加载可执行目录的namp 指纹文件,与数据文件
func Load() []model.NmapStruct {
	nmapStructs := make([]model.NmapStruct, 0)
	json.Unmarshal(nmapJson, &nmapStructs)
	return nmapStructs
}
