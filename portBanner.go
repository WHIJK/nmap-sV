package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"goPortBanner/model"
	"os"
	"strings"
	"sync"
	"time"
)

// 并发，线程池
var jobsChannel = make(chan string, 100)
var bannerChannel = make(chan string, 100)
var portList = make([]string, 0) // 端口符合，优先发送
var bannerStruct model.BannerResult

// 任务创建
func createJobs(s *bufio.Scanner) {
	for s.Scan() {
		if job, _, ok := matchIPPORT(fmt.Sprintf("%s", strings.ReplaceAll(s.Text(), " ", ""))); ok {
			jobsChannel <- job
		} else {
			fmt.Println(job + " input error")
		}
	}
	close(jobsChannel)
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

func init() {
	flag.Parse()
}

func main() {
	startTime := time.Now()
	//stat, _ := os.Stdin.Stat()
	//if (stat.Mode() & os.ModeCharDevice) != 0 {
	//	fmt.Fprintln(os.Stderr, "No input detected. Hint: cat ip:port.txt | file")
	//	os.Exit(1)
	//}
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
