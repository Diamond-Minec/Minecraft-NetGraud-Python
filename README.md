# Minecraft-NetGraud-Python
NetGuard 是一款专为网易我的世界租赁服务器设计的防锁服保护工具，使用标准 RakNet 协议建立合法连接，发送 ACK 确认包帮助服务器清理数据队列，抢占连接槽位抵御恶意攻击。  工具采用多线程并发防御，支持实时统计防御数据（发送/接收数据包、成功连接数），断线自动重连持续保护。运行环境要求 Python 3.6+，支持 Windows、Linux、macOS。使用时运行 python unlock.py ，输入目标服务器 IP、端口和防御线程数即可开始保护。  开发者为沧蓝工坊（群主Diamond），QQ群956766495提供技术支持，当前版本 v1.0 BETA。
