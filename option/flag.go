package option

import "flag"

/*
@Author: OvO
@Date: 2023/11/1 18:02
*/

var Threads = flag.Int("t", 50, "Threads")
var TaskNumber = flag.Int("n", 30, "the number of tasks each goruntine will handle when send and match") //会根据指定的任务数量分配goruntine的数量
var File = flag.String("o", "", "Output to  json")
var Pattern = flag.Bool("p", false, "show pattern")
var Banner = flag.Bool("b", false, "Show port banner")
var Model = flag.String("m", "all", "only tcp or only udp, tcp、udp、all")
var Info = flag.Bool("i", false, "Show all info")
var Timeout = flag.Int("time", 5, "timeout for port")
