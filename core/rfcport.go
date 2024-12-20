package core

// 定义常见仅支持 TCP 的端口号
var TcpOnlyPorts = map[string]bool{
	"22":    true,
	"80":    true,
	"443":   true,
	"3389":  true,
	"43":    true,
	"57":    true,
	"70":    true,
	"79":    true,
	"81":    true,
	"88":    true,
	"101":   true,
	"102":   true,
	"107":   true,
	"109":   true,
	"110":   true,
	"113":   true,
	"115":   true,
	"117":   true,
	"119":   true,
	"170":   true,
	"179":   true,
	"194":   true,
	"308":   true,
	"311":   true,
	"411":   true,
	"412":   true,
	"445":   true,
	"465":   true,
	"475":   true,
	"497":   true,
	"512":   true,
	"513":   true,
	"514":   true,
	"515":   true,
	"520":   true,
	"532":   true,
	"540":   true,
	"543":   true,
	"544":   true,
	"548":   true,
	"556":   true,
	"587":   true,
	"591":   true,
	"604":   true,
	"646":   true,
	"647":   true,
	"648":   true,
	"652":   true,
	"665":   true,
	"674":   true,
	"691":   true,
	"692":   true,
	"695":   true,
	"699":   true,
	"700":   true,
	"701":   true,
	"702":   true,
	"706":   true,
	"711":   true,
	"712":   true,
	"720":   true,
	"782":   true,
	"829":   true,
	"860":   true,
	"873":   true,
	"901":   true,
	"911":   true,
	"981":   true,
	"993":   true,
	"995":   true,
	"1025":  true,
	"1026":  true,
	"1029":  true,
	"1058":  true,
	"1059":  true,
	"1080":  true,
	"1099":  true,
	"1109":  true,
	"1140":  true,
	"1176":  true,
	"1214":  true,
	"1248":  true,
	"1311":  true,
	"1313":  true,
	"1337":  true,
	"1352":  true,
	"1387":  true,
	"1414":  true,
	"1431":  true,
	"1494":  true,
	"1521":  true,
	"1526":  true,
	"1533":  true,
	"1547":  true,
	"1677":  true,
	"1716":  true,
	"1723":  true,
	"1755":  true,
	"1761":  true,
	"1863":  true,
	"1935":  true,
	"1984":  true,
	"1994":  true,
	"1998":  true,
	"2000":  true,
	"2002":  true,
	"2031":  true,
	"2053":  true,
	"2073":  true,
	"2074":  true,
	"2082":  true,
	"2083":  true,
	"2086":  true,
	"2087":  true,
	"2095":  true,
	"2096":  true,
	"2161":  true,
	"2181":  true,
	"2200":  true,
	"2219":  true,
	"2220":  true,
	"2222":  true,
	"2301":  true,
	"2369":  true,
	"2370":  true,
	"2381":  true,
	"2404":  true,
	"2447":  true,
	"2598":  true,
	"2710":  true,
	"2735":  true,
	"2809":  true,
	"2948":  true,
	"2949":  true,
	"2967":  true,
	"3000":  true,
	"3001":  true,
	"3002":  true,
	"3003":  true,
	"3004":  true,
	"3006":  true,
	"3007":  true,
	"3025":  true,
	"3128":  true,
	"3260":  true,
	"3268":  true,
	"3269":  true,
	"3300":  true,
	"3333":  true,
	"3396":  true,
	"3689":  true,
	"3690":  true,
	"3724":  true,
	"3872":  true,
	"3899":  true,
	"3900":  true,
	"3945":  true,
	"4000":  true,
	"4007":  true,
	"4089":  true,
	"4093":  true,
	"4111":  true,
	"4224":  true,
	"4662":  true,
	"4664":  true,
	"4894":  true,
	"4899":  true,
	"5000":  true,
	"5001":  true,
	"5003":  true,
	"5050":  true,
	"5051":  true,
	"5060":  true,
	"5061":  true,
	"5104":  true,
	"5106":  true,
	"5107":  true,
	"5110":  true,
	"5121":  true,
	"5176":  true,
	"5190":  true,
	"5222":  true,
	"5223":  true,
	"5269":  true,
	"5432":  true,
	"5495":  true,
	"5498":  true,
	"5500":  true,
	"5501":  true,
	"5517":  true,
	"5555":  true,
	"5556":  true,
	"5631":  true,
	"5666":  true,
	"5667":  true,
	"5800":  true,
	"5900":  true,
	"6000":  true,
	"6005":  true,
	"6050":  true,
	"6051":  true,
	"6100":  true,
	"6110":  true,
	"6111":  true,
	"6112":  true,
	"6129":  true,
	"6522":  true,
	"6566":  true,
	"6600":  true,
	"6665":  true,
	"6679":  true,
	"6697":  true,
	"6699":  true,
	"6969":  true,
	"7000":  true,
	"7001":  true,
	"7002":  true,
	"7010":  true,
	"7025":  true,
	"7047":  true,
	"7171":  true,
	"7306":  true,
	"7307":  true,
	"7670":  true,
	"7777":  true,
	"8000":  true,
	"8002":  true,
	"8008":  true,
	"8009":  true,
	"8010":  true,
	"8074":  true,
	"8080":  true,
	"8086":  true,
	"8087":  true,
	"8090":  true,
	"8118":  true,
	"8200":  true,
	"8220":  true,
	"8291":  true,
	"8294":  true,
	"8443":  true,
	"8500":  true,
	"8881":  true,
	"8882":  true,
	"8888":  true,
	"9000":  true,
	"9001":  true,
	"9043":  true,
	"9060":  true,
	"9100":  true,
	"9535":  true,
	"10024": true,
	"10025": true,
	"10050": true,
	"10051": true,
	"10113": true,
	"10114": true,
	"10115": true,
	"10116": true,
	"12975": true,
	"13720": true,
	"13721": true,
	"13724": true,
	"13782": true,
	"13783": true,
	"15000": true,
	"16000": true,
	"16080": true,
	"19226": true,
	"19638": true,
	"19813": true,
	"20720": true,
	"25999": true,
	"26000": true,
	"30564": true,
	"31337": true,
	"31456": true,
	"31457": true,
	"31458": true,
	"32245": true,
	"37777": true,
	"43594": true,
	"43595": true,
}
