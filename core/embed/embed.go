package embed

import (
	_ "embed"
	"encoding/json"
	"github.com/WHIJK/nmap-sV/core/model"
)

/*
@Author: OvO
@Date: 2023/11/1 17:31
*/

//go:embed nmap.json
var nmapJson []byte

//go:embed new.json
var newJson []byte

// 加载可执行目录的namp 指纹文件,与数据文件
func Load() []model.NmapStruct {
	nmapStructs := make([]model.NmapStruct, 0)
	newStructs := make([]model.NmapStruct, 0)
	json.Unmarshal(nmapJson, &nmapStructs)
	json.Unmarshal(newJson, &newStructs)
	newStructs = append(newStructs, nmapStructs...)
	return newStructs
}
