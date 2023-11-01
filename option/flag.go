package option

import "flag"

/*
@Author: OvO
@Date: 2023/11/1 18:02
*/

var Threads = flag.Int("thread", 100, "Threads")
var File = flag.String("o", "", "Output to  json")
var Banner = flag.Bool("b", false, "Show port banner")

// var SendData = flag.String("s", "All", "Send data,Example: rdp,http")
var Info = flag.Bool("i", false, "Show all info")
var Timeout = flag.Int("time", 3, "timeout for port")
