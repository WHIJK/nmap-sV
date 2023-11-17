package util

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"github.com/WHIJK/nmap-sV/option"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

/*
@Author: OvO
@Date: 2023/11/1 17:33
*/

// 正则匹配,需要强行转换成UTF-8
func ConvResponse(s1 string) string {
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

/*
HexToString
@Description: 从json文件中获得的是字符串，需要将其转化为 \u 、\x转化为对应的字符串
@param hexstr
@return string
*/
func HexToString(hexstr string) string { // hexstr example: \\x25\\x00\\x00\\x00\\x00,
	hexstr = strings.ReplaceAll(hexstr, "\\0", "\\x00")
	unicodeRegex := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	decodedString := unicodeRegex.ReplaceAllStringFunc(hexstr, func(match string) string {
		codePoint, err := strconv.ParseUint(match[2:], 16, 32)
		if err != nil {
			return match
		}
		return string(rune(codePoint))
	})

	reg1 := regexp.MustCompile(`\\x([0-9a-zA-Z][0-9a-zA-Z])`) // 匹配\x+16进制字符
	result := reg1.FindAllStringSubmatch(decodedString, -1)   // 将获得例如： [\x25 =》25] [\x00 =》 00]
	for _, v := range result {                                //
		if !strings.Contains(decodedString, v[1]) {
			continue
		}
		a, _ := hex.DecodeString(v[1])
		decodedString = strings.Replace(decodedString, v[0], string(a), -1)
	}
	return decodedString
}

// 字符串连接
func BufferJoin(s1 []string) string {
	var buffer bytes.Buffer
	for _, s := range s1 {
		buffer.WriteString(s)
	}
	return buffer.String()
}

// output
func W2json(one string) {
	file, err := os.OpenFile(*option.File, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	write.WriteString(one + "\n")
	write.Flush()
}

/*
MatchInput
@Description: 验证输入是否合法
@param ip
@return string
@return string
@return bool
*/
func MatchInput(input string) (string, bool) {
	var inputSplit = []string{}
	if stringsutil.ContainsAnyI(input, ":") {
		inputSplit = stringsutil.SplitAny(input, ":")
		if len(inputSplit) != 2 || !iputil.IsPort(inputSplit[1]) {
			return input, false
		}
	} else {
		return strings.Join([]string{input, "80"}, ":"), true
	}
	return input, true
}

// 处理端口范围
func PortHandle(ports []string) []string {
	var newPorts []string
	for i, _ := range ports {
		if strings.Contains(ports[i], "-") {
			rangePort := strings.Split(ports[i], "-")
			nums_start, _ := strconv.Atoi(rangePort[0])
			nums_end, _ := strconv.Atoi(rangePort[1])
			for j := nums_start; j <= nums_end; j++ {
				newPorts = append(newPorts, strconv.Itoa(j))
			}
		} else {
			newPorts = append(newPorts, ports[i])
		}
	}
	return newPorts
}

/*
StrInSlice
@Description:  判断target是否在slice中
@param target
@param str_array
@return bool
*/
func StrInSlice(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	//index的取值：[0,len(str_array)]
	if index < len(str_array) && str_array[index] == target { //需要注意此处的判断，先判断 &&左侧的条件，如果不满足则结束此处判断，不会再进行右侧的判断
		return true
	}
	return false
}
