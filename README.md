# portBanner

Port fingerprint recognition  
[only tcp  !!!!!]
```
No input detected. Hint: cat ip:port.txt | file
Usage of portBanner:
  -b    Show port banner
  -i    Show all info
  -o string
        Output to  json file
  -s string
        Send data,Example: rdp,http (default "All")
  -t int
        Threads (default 100)
```
nmapfinger.py can convert nmap-service-probes to nmap.json

**When add finger,  all \x0 need replaced by \x00 in nmap.json !!!!**


![image](./example.png)
