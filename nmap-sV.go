package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"goPortBanner/core"
	"goPortBanner/core/model"
	"goPortBanner/core/util"
	"goPortBanner/option"
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
		if job, _, ok := util.MatchIPPORT(fmt.Sprintf("%s", strings.ReplaceAll(s.Text(), " ", ""))); ok {
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
		if *option.File != "" {
			util.W2json(v)
		}
		json.Unmarshal([]byte(v), &bannerStruct)

		print_info := fmt.Sprintf("%-10s %s ", bannerStruct.Address, bannerStruct.Service)
		if *option.Info {
			print_info = util.BufferJoin([]string{print_info, " (", bannerStruct.Banner.Vendorproductname})
			if bannerStruct.Banner.Version != "" {
				print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Banner.Version, ") "})
			} else {
				print_info = util.BufferJoin([]string{print_info, ") ", bannerStruct.Banner.Operatingsystem})
			}
		}
		if *option.Banner {
			print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Banner.BannerPrint})
		}
		fmt.Println(print_info)
	}
	done <- true
}

// 创建线程池
func createPool(threads int) {
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(&wg)
	}
	wg.Wait()
	close(bannerChannel)
}

// 执行任务
func worker(wg *sync.WaitGroup) {
	for v := range jobsChannel {
		core.Run(v, bannerChannel)
	}
	wg.Done()
}

func init() {
	flag.Parse()
}

func main() {
	startTime := time.Now()
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No input detected. Hint: cat ip:port.txt | nmap-sV")
		os.Exit(1)
	}
	s := bufio.NewScanner(os.Stdin)
	go createJobs(s)
	done := make(chan bool)
	go printBanner(done)
	createPool(*option.Threads)
	<-done
	endTime := time.Now()
	diffTime := endTime.Sub(startTime).Seconds()
	fmt.Printf("\nTake %f seconds", diffTime)
}
