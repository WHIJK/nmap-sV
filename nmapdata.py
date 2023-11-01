import re
import json,os
import itertools

def parse_file(file_content):
    pattern = r'Probe TCP (\w+) q\|(.*?)\|\s*(?:rarity \d\s*)?(?:ports|sslports) (.*?)(?:\s*rarity \d)?(?=\s*[^p]|$)\n'
    matches = re.findall(pattern, file_content, re.MULTILINE)
    results = []
    for match in matches:
        name = match[0]
        data = match[1]
        ports = match[2].split(',')
        results.append({
            "name": name,
            "data": data.replace('\\r\\n', '\r\n'),
            "port": ports,
        })
    return results


# 跳过# 开头
with open('nmap-service-probes', 'r', encoding='utf-8') as f, open('output.txt', 'w', encoding='utf-8') as out_f:
    for line in itertools.islice(f, 5000, None):
        if line.startswith('#'):
            continue
        out_f.write(line)

# 从文件中读取内容

with open('output.txt', 'r',encoding='utf-8') as f:
    for line in itertools.islice(f, 5000, None):
        file_content = f.read()

# 解析文件内容
results = parse_file(file_content)

# 将结果写入到新的文件中
with open('data.json', 'w') as f:
    f.write(json.dumps(results, indent=4))

os.remove('output.txt')