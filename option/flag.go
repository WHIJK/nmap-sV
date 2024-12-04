package option

import (
	"flag"
)

/*
@Author: OvO
@Date: 2023/11/1 18:02
*/

var (
	Threads    int
	TaskNumber int
	File       string
	Pattern    bool
	Banner     bool
	Model      string
	Info       bool
	Timeout    int
	Host       string
	Script     bool // 默认值为启用
)

func init() {
	flag.IntVar(&Threads, "t", 50, "Threads")
	flag.IntVar(&TaskNumber, "n", 30, "the number of tasks each goroutine will handle when send and match")
	flag.StringVar(&File, "o", "", "Output to json")
	flag.BoolVar(&Pattern, "p", false, "show pattern")
	flag.BoolVar(&Banner, "b", false, "Show port banner")
	flag.StringVar(&Model, "m", "all", "only tcp or only udp, tcp、udp、all")
	flag.BoolVar(&Info, "i", false, "Show all info")
	flag.IntVar(&Timeout, "time", 5, "timeout for port")
	flag.StringVar(&Host, "e", "", "Enter a target")
	flag.BoolVar(&Script, "d", false, "Disabled script")
}
