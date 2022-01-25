package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// nmap json
type NmapStruct struct {
	Protocol     string        `json:"protocol"`
	Probename    string        `json:"probename"`
	Probestring  string        `json:"probestring"`
	Ports        []interface{} `json:"ports"`
	Sslports     []interface{} `json:"sslports"`
	Totalwaitms  string        `json:"totalwaitms"`
	Tcpwrappedms string        `json:"tcpwrappedms"`
	Rarity       string        `json:"rarity"`
	Fallback     string        `json:"fallback"`
	Matches      []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"matches"`
	Softmatches []struct {
		Pattern     string `json:"pattern"`
		Name        string `json:"name"`
		PatternFlag string `json:"pattern_flag"`
		Versioninfo struct {
			Cpename           string `json:"cpename"`
			Devicetype        string `json:"devicetype"`
			Hostname          string `json:"hostname"`
			Info              string `json:"info"`
			Operatingsystem   string `json:"operatingsystem"`
			Vendorproductname string `json:"vendorproductname"`
			Version           string `json:"version"`
		} `json:"versioninfo"`
	} `json:"softmatches"`
}

// 发送的json文件
type DataStrut struct {
	Name string   `json:"name"`
	Data string   `json:"data"`
	Port []string `json:"port"`
}

// 结果struct
type BannerResult struct {
	Address string `json:"address"`
	Service string `json:""`
	Banner  struct {
		Operatingsystem   string `json:"operatingsystem"`
		Vendorproductname string `json:"vendorproductname"`
		Version           string `json:"version"`
		BannerPrint       string `json:"bannerPrint"`
	}
}

// 加载可执行目录的namp 指纹文件,与数据文件
func loadPrint(dataFile string) ([]NmapStruct, []DataStrut) {
	nmapStructs := make([]NmapStruct, 0)
	dataStruts := make([]DataStrut, 0)
	ex, _ := os.Executable()   // 获取可执行文件信息
	exPath := filepath.Dir(ex) // 文件路径
	content, err := ioutil.ReadFile(exPath + "/" + dataFile)
	// content, err := ioutil.ReadFile(dataFile)
	if err != nil {
		fmt.Println("load " + dataFile + " fail")
		os.Exit(1)
	}
	jsonAsBytes := []byte(string(content))
	switch dataFile {
	case "nmap.json":
		json.Unmarshal(jsonAsBytes, &nmapStructs)
	case "data.json":
		json.Unmarshal(jsonAsBytes, &dataStruts)
	}
	return nmapStructs, dataStruts
}

// 正则匹配,需要强行转换成UTF-8
func convResponse(s1 string) string {
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

//从json文件中获得的是字符串，需要将它转化为\x16进制格式
func hexToString(hexstr string) string { // hexstr example: \\x25\\x00\\x00\\x00\\x00,
	// fmt.Printf("%#v\n", hexstr)
	reg1 := regexp.MustCompile(`\\x([0-9a-zA-Z][0-9a-zA-Z])`) // 匹配\x+16进制字符
	result := reg1.FindAllStringSubmatch(hexstr, -1)          // 将获得 [\x25 25] [\x00 00]
	for _, v := range result {                                //
		if !strings.Contains(hexstr, v[1]) {
			continue
		}
		a, _ := hex.DecodeString(v[1])
		hexstr = strings.Replace(hexstr, v[0], string(a), -1)
	}
	// fmt.Printf("%#v", hexstr)
	return hexstr
}

// 字符串连接
func bufferJoin(s1 []string) string {
	var buffer bytes.Buffer
	for _, s := range s1 {
		buffer.WriteString(s)
	}
	return buffer.String()
}

// 请求获取Banner
func GetBanner(address string, nmapStructs []NmapStruct, dataStruts []DataStrut) {
	buf := make([]byte, 2048)
	var bannerResult BannerResult // banner结果存储
	var matchFlag bool            // 是否成功匹配指纹标志位

	Service := ""
	Operatingsystem := ""
	Vendorproductname := ""
	Version := ""
	i := 0 // 发送data顺序
start:
	conn, err := net.DialTimeout("tcp", address, time.Second*2) // 端口扫描
	if err == nil {
		dataList := getNeedFromSendData(strings.Split(address, ":")[1], dataStruts)
		defer conn.Close()
		var result string      // 转化为字符串后的结果
		var bannerPrint string // 记录端口的banner信息
		conn.SetDeadline(time.Now().Add(time.Second * 2))
		io.WriteString(conn, hexToString(dataList[i]))
		length, err_read := conn.Read(buf)

		if err_read == nil && length > 0 {
			bannerPrint = string(buf[:length]) // 获得指纹信息
			for i := 0; i < len(nmapStructs); i++ {
				for _, match := range nmapStructs[i].Matches {
					var pattern string
					var matchArr []string //
					// 设置匹配标志位
					if match.PatternFlag != "" {
						pattern = bufferJoin([]string{"(?", match.PatternFlag, ")", match.Pattern})
					} else {
						pattern = match.Pattern
					}
					matchArr, matchFlag = MatchFingerprint(convResponse(bannerPrint), pattern)
					if matchFlag { // 匹配到json文件中的正则
						Service = match.Name
						Operatingsystem = MatchGroup(match.Versioninfo.Operatingsystem, matchArr)
						Vendorproductname = MatchGroup(match.Versioninfo.Vendorproductname, matchArr)
						Version = MatchGroup(match.Versioninfo.Version, matchArr)
						goto endone // 获取了匹配结果，跳转写入通道
					}
				}
			}

		} else if length == 0 && i < len(dataList)-1 { //重新发送数据，找指纹
			i++
			goto start
		}
		if !matchFlag {
			// 未获取正则或者返回内容，但端口开放，则设定默认值
			Service = "Unkown"
			Operatingsystem = ""
			Vendorproductname = ""
			Version = ""

		}
	endone: // 写入通道
		cc := strings.Trim(fmt.Sprintf("%#v", string(bannerPrint)), `\"`)
		bannerResult = BannerResult{
			Address: address,
			Service: Service,
			Banner: struct {
				Operatingsystem   string `json:"operatingsystem"`
				Vendorproductname string `json:"vendorproductname"`
				Version           string `json:"version"`
				BannerPrint       string `json:"bannerPrint"`
			}{
				Operatingsystem:   Operatingsystem,
				Vendorproductname: Vendorproductname,
				Version:           Version,
				BannerPrint:       cc,
			},
		}
		a, _ := json.Marshal(bannerResult)
		result = string(a)
		bannerChannel <- result
	} else {
		fmt.Println(address, " Timeout")
	}
}

//将分组匹配信息替换到对应的$1、$2上
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

func w2json(one string) {
	file, err := os.OpenFile(*file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	write.WriteString(one + "\n")
	write.Flush()
}

// 并发，线程池
var jobsChannel = make(chan string, 100)
var bannerChannel = make(chan string, 100)
var portList = make([]string, 0) // 端口符合，优先发送
var bannerStruct BannerResult

// 验证输入是否合法
func matchIPPORT(ip string) (string, string, bool) {
	port := ""
	if !strings.Contains(ip, ":") {
		if matchIP(ip) {
			job := strings.Join([]string{ip, "80"}, ":")
			port = "80"
			return job, port, true
		}
	} else {
		ip_port := strings.Split(ip, ":")
		port = ip_port[1]
		if matchIP(ip_port[0]) {
			return ip, port, true
		}
	}

	return ip, port, false
}

// 验证IP有效性
func matchIP(ip string) bool {
	if isIP := net.ParseIP(ip); isIP != nil {
		return true
	}
	return false
}

// 任务创建
func createJobs(s *bufio.Scanner) {
	for s.Scan() {
		if job, _, ok := matchIPPORT(s.Text()); ok {
			jobsChannel <- job
		} else {
			fmt.Println(job + " input error")
		}
	}
	close(jobsChannel)
}

// 获取发送的数据,由于发送数据时是按顺序的，将符合条件的端口放在第一个数据发送
func getNeedFromSendData(target_port string, dataStruts []DataStrut) []string {
	dataList := []string{} // 初始化
	if strings.ToLower(*sendData) == "all" {
		for i, _ := range dataStruts {
			newPorts := portHandle(dataStruts[i].Port)
			if in(target_port, newPorts) {
				dataList = append([]string{dataStruts[i].Data}, dataList...) // 找到端口匹配，放在数据切片的头部
			} else {
				dataList = append(dataList, dataStruts[i].Data)
			}
		}
	} else {
		for i, _ := range dataStruts {
			if strings.Contains(*sendData, dataStruts[i].Name) {
				newPorts := portHandle(dataStruts[i].Port)
				if in(target_port, newPorts) {
					dataList = append([]string{dataStruts[i].Data}, dataList...) // 找到端口匹配，放在数据切片的头部
				} else {
					dataList = append(dataList, dataStruts[i].Data)
				}
			}
		}
	}
	return dataList
}

// 处理端口范围
func portHandle(ports []string) []string {
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

// 二分法查找端口
func in(target string, str_array []string) bool {
	sort.Strings(str_array)
	index := sort.SearchStrings(str_array, target)
	//index的取值：[0,len(str_array)]
	if index < len(str_array) && str_array[index] == target { //需要注意此处的判断，先判断 &&左侧的条件，如果不满足则结束此处判断，不会再进行右侧的判断
		return true
	}
	return false
}

// 输出
func printBanner(done chan bool) {
	for v := range bannerChannel {
		if *file != "" {
			w2json(v)
		}
		json.Unmarshal([]byte(v), &bannerStruct)

		print_info := fmt.Sprintf("%-10s %s ", bannerStruct.Address, bannerStruct.Service)
		if *info {
			print_info = bufferJoin([]string{print_info, " (", bannerStruct.Banner.Vendorproductname})
			if bannerStruct.Banner.Version != "" {
				print_info = bufferJoin([]string{print_info, " ", bannerStruct.Banner.Version, ") "})
			} else {
				print_info = bufferJoin([]string{print_info, ") ", bannerStruct.Banner.Operatingsystem})
			}
		}
		if *banner {
			print_info = bufferJoin([]string{print_info, " ", bannerStruct.Banner.BannerPrint})
		}
		fmt.Println(print_info)
	}
	done <- true
}

// 创建线程池
func createPool(threads int) {
	nmapStructs, _ := loadPrint("nmap.json") // 加载文件
	_, dataStruts := loadPrint("data.json")
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(&wg, nmapStructs, dataStruts)

	}
	wg.Wait()
	close(bannerChannel)
}

// 执行任务
func worker(wg *sync.WaitGroup, nmapStructs []NmapStruct, dataStruts []DataStrut) {
	for v := range jobsChannel {
		GetBanner(v, nmapStructs, dataStruts)
	}
	wg.Done()
}

var threads = flag.Int("t", 100, "Threads")
var file = flag.String("o", "", "Output to  json file ")
var banner = flag.Bool("b", false, "Show port banner")
var sendData = flag.String("s", "All", "Send data,Example: rdp,http")
var info = flag.Bool("i", false, "Show all info")

func main() {
	flag.Parse()
	startTime := time.Now()
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No input detected. Hint: cat ip:port.txt | file")
		os.Exit(1)
	}
	s := bufio.NewScanner(os.Stdin)
	go createJobs(s)
	done := make(chan bool)
	go printBanner(done)
	createPool(*threads)
	<-done
	endTime := time.Now()
	diffTime := endTime.Sub(startTime).Seconds()
	fmt.Printf("\nTake %f seconds", diffTime)
}
