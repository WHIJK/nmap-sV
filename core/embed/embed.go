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

/*
Load
@Description: 加载可执行目录的namp 指纹文件,与数据文件
@return []model.NmapStruct
*/
func Load() []model.NmapStruct {
	var nmapStructs, newStructs []model.NmapStruct
	json.Unmarshal(nmapJson, &nmapStructs)
	json.Unmarshal(newJson, &newStructs)
	newStructs = append(newStructs, nmapStructs...)
	return newStructs
}
