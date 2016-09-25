# Fortigate-autopwn
NSA EQG泄漏的飞塔防火墙溢出工具设置太复杂，自己写的一个全自动化脚本
# 运行方法
直接拉到本地赋予权限后执行就好，因为流程实在太复杂，而且规则固定，所以写的全自动的脚本
- 自动检测同文件夹下是否有egregiousblunder_3.0.0.1，如果无直接输出生成好的命令，可供粘贴到另外的环境里去运行，如果有直接执行EXP
- 自动判断飞塔防火墙型号，生成不同的溢出命令
- 自动判断协议是SSL还是HTTP以及端口
# Usage
````
$ git clone https://github.com/killerhack/Fortigate-autopwn
$ chmod 775 fortinet_autopwn.py egregiousblunder_3.0.0.1
$ fortinet_autopwn.py http(s)://target_ip:port
````
# 依赖库
- subprocess
- requests
- shlex  

如果提示import error请pip install该模块  

#说明
其中的文件全部是NSA Equtation group原版，除过CONF文件中修改了NOSERVER以及NOCLIENT的路径。
