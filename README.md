# REF
- https://github.com/boy-hack/nmap-parser  
- https://github.com/lcvvvv/gonmap
- https://github.com/nmap/nmap
- https://github.com/projectdiscovery/naabu

# nmap-sV
使用nmap指纹，利用go实现指纹探测
>- **未匹配到可能会很慢**
>- new.json为新增加的探针与对应的规则
>- 已有探针上添加匹配规则，使用AddPattern函数
>- 支持域名，未添加端口则默认为80
```
No input detected. Hint: cat ip:port.txt | file
Usage of nmap-sV:
  -b    Show port banner
  -i    Show all info
  -o string
        Output to  json 
  -thread int
        Threads (default 100)
  -time int
        timeout for port (default 5)

```

![image](img/example.png)  
从naabu获取输入  
![img.png](img/img.png)