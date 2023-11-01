package core

import (
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
