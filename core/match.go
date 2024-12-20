package core

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/projectdiscovery/gologger"
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
func MatchFingerprint(banner, reg, flag string) ([]string, bool) {
	var re *regexp2.Regexp
	switch flag {
	case "s":
		re = regexp2.MustCompile(reg, regexp2.Singleline)
	case "i":
		re = regexp2.MustCompile(reg, regexp2.IgnoreCase)
	default:
		re = regexp2.MustCompile(reg, regexp2.Multiline|regexp2.IgnoreCase)
	}

	if ok, err := re.MatchString(banner); ok && err == nil {
		if match, match_err := re.FindStringMatch((banner)); match_err == nil {
			var matchGroup = []string{}
			if match != nil && len(match.Groups()) > 1 {
				for i, group := range match.Groups() {
					if i != 0 && len(group.Captures) != 0 {
						matchGroup = append(matchGroup, group.Captures[0].String())
					}
				}
			}
			return matchGroup, true
		} else {
			gologger.Error().Msg(match_err.Error())
		}
	}
	return []string{}, false
}
