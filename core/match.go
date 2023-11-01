package core

import (
	"goPortBanner/model"
	"regexp"
	"strconv"
	"strings"
)

/*
@Author: OvO
@Date: 2023/11/1 17:34
*/

// 将分组匹配信息替换到对应的$1、$2上
func MatchGroup(src string, replace_text []string) string {
	reg := `\$\d`
	if ok, _ := regexp.MatchString(reg, src); ok {
		compile, _ := regexp.Compile(reg)
		repl, _ := strconv.Atoi(strings.TrimLeft(compile.FindString(src), "$")) // 获取 $1,$2 的数字
		dsr_str := compile.ReplaceAllString(src, replace_text[repl-1])
		return dsr_str
	}
	return src
}

// 指纹匹配
func MatchFingerprint(banner, reg string) ([]string, bool) {
	if ok, _ := regexp.MatchString(reg, banner); ok {
		compile, _ := regexp.Compile(reg)
		match_arr := compile.FindStringSubmatch(banner)
		return match_arr[1:], true // 只获取分组
	}
	return []string{}, false
}

/*
AddPattern
@Description: 添加规则
@param probename  在哪一个添加规则
@param pattern
@param name
@param pattern_flag
@param cpename
@param devicetype
@param hostname
@param info
@param operatingsystem
@param vendorproductname
@param version
@return model.Matches
*/
func AddPattern(nmapStructs *[]model.NmapStruct, probename, pattern, name, pattern_flag, cpename, devicetype, hostname, info, operatingsystem, vendorproductname, version string) {
	type Versioninfo struct {
		Cpename           string `json:"cpename"`
		Devicetype        string `json:"devicetype"`
		Hostname          string `json:"hostname"`
		Info              string `json:"info"`
		Operatingsystem   string `json:"operatingsystem"`
		Vendorproductname string `json:"vendorproductname"`
		Version           string `json:"version"`
	}
	var Matches = model.Matches{
		Pattern:     strings.ReplaceAll(pattern, `\x00`, `\0`),
		Name:        name,
		PatternFlag: pattern_flag,
		Versioninfo: Versioninfo{
			Cpename:           cpename,
			Devicetype:        devicetype,
			Hostname:          hostname,
			Info:              info,
			Operatingsystem:   operatingsystem,
			Vendorproductname: vendorproductname,
			Version:           version,
		},
	}
	for i, nmapStruct := range *nmapStructs {
		if nmapStruct.Probename == probename {
			(*nmapStructs)[i].Matches = append(nmapStruct.Matches, Matches)
			break
		}
	}
}
