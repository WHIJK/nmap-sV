package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/WHIJK/nmap-sV/core"
	"github.com/WHIJK/nmap-sV/core/model"
	"github.com/WHIJK/nmap-sV/core/util"
	"github.com/WHIJK/nmap-sV/option"
)

const version = "1.6.1"

// 并发，线程池
var jobsChannel = make(chan string, 100)
var bannerChannel = make(chan string, 100)
var portList = make([]string, 0) // 端口符合，优先发送
var bannerStruct model.BannerResult

// 任务创建
func createJobs(s bufio.Scanner) {
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		if job, ok := util.MatchInput(fmt.Sprintf("%s", strings.ReplaceAll(s.Text(), " ", ""))); ok {
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
		if option.File != "" {
			util.W2json(v)
		}
		json.Unmarshal([]byte(v), &bannerStruct)

		print_info := fmt.Sprintf("%-10s %s ", bannerStruct.Address, bannerStruct.Service)
		if option.Info {
			print_info = util.BufferJoin([]string{print_info, " (", bannerStruct.Banner.Vendorproductname})
			if bannerStruct.Banner.Version != "" {
				print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Banner.Version, ") "})
			} else {
				print_info = util.BufferJoin([]string{print_info, ") ", bannerStruct.Banner.Operatingsystem})
			}

		}
		if option.Banner {
			print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Banner.BannerPrint})
		}

		if option.Pattern {
			print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Pattern})
		}

		if bannerStruct.Banner.Extra != "" {
			print_info = util.BufferJoin([]string{print_info, " ", bannerStruct.Banner.Extra})
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
		core.Run(v, bannerChannel, option.TaskNumber, !option.Script)
	}
	wg.Done()
}

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s Usage: %s [options]\n", version, os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
	}
	flag.Parse()

}

func main() {
	startTime := time.Now()
	stat, _ := os.Stdin.Stat()
	if (stat.Mode()&os.ModeCharDevice) != 0 && option.Host == "" {
		fmt.Fprintln(os.Stderr, "No input detected. Hint: cat ip:port.txt | nmap-sV")
		os.Exit(1)
	}
	var inputReader io.Reader
	if option.Host != "" {
		inputReader = io.MultiReader(strings.NewReader(option.Host+"\n"), os.Stdin)
	} else {
		inputReader = os.Stdin
	}
	s := bufio.NewScanner(inputReader)
	go createJobs(*s)
	done := make(chan bool)
	go printBanner(done)
	createPool(option.Threads)
	<-done
	endTime := time.Now()
	diffTime := endTime.Sub(startTime).Seconds()
	fmt.Printf("\nTake %f seconds", diffTime)
}
