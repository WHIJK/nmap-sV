package file

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

//go:embed data.json
var dataJson []byte

// 加载可执行目录的namp 指纹文件,与数据文件
func loadPrint(dataFile string) ([]model.NmapStruct, []model.DataStrut) {
	nmapStructs := make([]model.NmapStruct, 0)
	dataStruts := make([]model.DataStrut, 0)
	switch dataFile {
	case "nmap.json":
		json.Unmarshal(nmapJson, &nmapStructs)
	case "data.json":
		json.Unmarshal(dataJson, &dataStruts)
	}
	return nmapStructs, dataStruts
}
