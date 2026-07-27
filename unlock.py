import socket
import struct
import random
import time
import sys
import threading
import hashlib

VERSION = 'v1.0'
MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'

成功连接 = 0
防御次数 = 0
发送数据包 = 0
接收数据包 = 0
拦截NACK = 0
拦截攻击连接 = 0
拦截握手攻击 = 0
服务器状态 = '检测中...'
连续失败次数 = 0
锁 = threading.Lock()

绿色 = '\033[92m'
红色 = '\033[91m'
灰色 = '\033[90m'
黄色 = '\033[93m'
蓝色 = '\033[94m'
重置 = '\033[0m'

攻击IP黑名单 = set()
正常连接列表 = {}
最近握手记录 = {}


def xor_cipher(data, key):
    return bytes(a ^ b for a, b in zip(data, key * ((len(data) // len(key)) + 1)))


def _decode_meta():
    k = b'NG2026X9#KL$%87'
    d = b'\xa8\xf5\x95\xd8\xa1\xab\xbd\x8e\x86\xae\xd1\xae\xca\x84\xbf\xa9\xf9\x96\xd4\x8a\x8d\x1cPB&#JA\xd7\x8b\xc7'
    q = b'wr\x04\x07\x04\x00l\x00\x16'
    try:
        return xor_cipher(d, k).decode('utf-8'), xor_cipher(q, k).decode('utf-8')
    except:
        print(f'{红色}[错误] 元数据解码失败!{重置}')
        sys.exit(1)


def _verify():
    try:
        global NG_SECURITY_TOKEN
        if not NG_SECURITY_TOKEN:
            print(f'{红色}[错误] 安全检查失败!{重置}')
            sys.exit(1)
        
        with open(__file__, 'r', encoding='utf-8') as f:
            c = f.read()
            if 'NG_SECURITY_TOKEN = True' not in c:
                print(f'{红色}[错误] 安全检查失败!{重置}')
                sys.exit(1)
        
        return True
    except:
        print(f'{红色}[错误] 安全验证失败!{重置}')
        sys.exit(1)


def 创建合法Ping包():
    return bytes([0x05]) + MAGIC + bytes([8]) + b'\x00' * 20


def 创建合法OpenConnectionRequest(host, port, guid):
    ip_enc = bytes(b ^ 0xFF for b in socket.inet_aton(host))
    return (bytes([0x07]) + MAGIC
            + bytes([0x04]) + ip_enc + struct.pack('>H', port)
            + struct.pack('>H', 1400)
            + struct.pack('>Q', guid))


def 创建合法ConnectionRequest(guid):
    conn_req = bytes([0x09]) + struct.pack('>Q', guid) + struct.pack('>Q', 0) + bytes([0])
    frame = bytes([0x40]) + struct.pack('>H', len(conn_req) * 8) + struct.pack('<I', 0)[:3] + conn_req
    return bytes([0x84]) + struct.pack('<I', 0)[:3] + frame


def 创建合法ACK(seq):
    return bytes([0xC0, 0x00, 0x01,
                  seq & 0xFF, (seq >> 8) & 0xFF, (seq >> 16) & 0xFF, 0x00])


def 创建合法NIC(host, port):
    entry4 = bytes([0x04]) + socket.inet_aton(host) + struct.pack('>H', port) + b'\x00' * 10
    entry6 = bytes([0x06]) + b'\x00' * 28
    nic = bytes([0x13]) + entry4 + entry6 * 9 + struct.pack('>Q', 0) + struct.pack('>Q', 0)
    f2 = bytes([0x40]) + struct.pack('>H', len(nic) * 8) + struct.pack('<I', 1)[:3] + nic
    return bytes([0x84]) + struct.pack('<I', 1)[:3] + f2


def 检测服务器(host, port):
    global 服务器状态, 连续失败次数
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    try:
        pkt = 创建合法Ping包()
        sock.sendto(pkt, (host, port))
        
        r, _ = sock.recvfrom(2048)
        if r[0] == 0x06:
            状态 = '在线'
            连续失败次数 = 0
        else:
            状态 = '未知'
            连续失败次数 = 0
    except socket.timeout:
        连续失败次数 += 1
        if 连续失败次数 >= 3:
            状态 = '离线/卡顿'
        else:
            状态 = '检测中...'
    except Exception:
        连续失败次数 += 1
        if 连续失败次数 >= 3:
            状态 = '连接失败'
        else:
            状态 = '检测中...'
    finally:
        sock.close()
    
    with 锁:
        服务器状态 = 状态
    return 状态


def 获取状态颜色(状态):
    if 状态 == '在线':
        return 绿色
    elif 状态 == '未知':
        return 灰色
    elif 状态 == '检测中...':
        return 黄色
    else:
        return 红色


def 攻击检测(ip, 数据包类型):
    global 攻击IP黑名单, 正常连接列表, 最近握手记录, 拦截握手攻击
    
    当前时间 = time.time()
    with 锁:
        if ip in 攻击IP黑名单:
            return True
        
        if ip not in 正常连接列表:
            正常连接列表[ip] = {'nack_count': 0, 'total_packets': 0, 'handshake_count': 0, 'last_activity': 当前时间}
        
        正常连接列表[ip]['total_packets'] += 1
        正常连接列表[ip]['last_activity'] = 当前时间
        
        if 数据包类型 == 'NACK':
            正常连接列表[ip]['nack_count'] += 1
            
            if 正常连接列表[ip]['nack_count'] >= 5:
                攻击IP黑名单.add(ip)
                print(f'{红色}[攻击检测] IP {ip} 发送大量NACK包，已加入黑名单!{重置}')
                return True
        
        elif 数据包类型 == 'HANDSHAKE':
            正常连接列表[ip]['handshake_count'] += 1
            
            if ip not in 最近握手记录:
                最近握手记录[ip] = []
            最近握手记录[ip].append(当前时间)
            
            if len(最近握手记录[ip]) > 20:
                最近握手记录[ip].pop(0)
            
            if 正常连接列表[ip]['handshake_count'] >= 30:
                攻击IP黑名单.add(ip)
                拦截握手攻击 += 正常连接列表[ip]['handshake_count']
                print(f'{红色}[攻击检测] IP {ip} 握手频率异常，已加入黑名单!{重置}')
                return True
    
    return False


def 清理过期连接():
    global 正常连接列表, 最近握手记录
    
    当前时间 = time.time()
    with 锁:
        for ip in list(正常连接列表.keys()):
            if 当前时间 - 正常连接列表[ip]['last_activity'] > 60:
                del 正常连接列表[ip]
        
        for ip in list(最近握手记录.keys()):
            最近握手记录[ip] = [t for t in 最近握手记录[ip] if 当前时间 - t < 10]
            if not 最近握手记录[ip]:
                del 最近握手记录[ip]


def 代理转发线程(本地端口, 目标主机, 目标端口):
    global 发送数据包, 接收数据包, 拦截攻击连接, 拦截NACK
    
    本地socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    本地socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    本地socket.bind(('0.0.0.0', 本地端口))
    本地socket.settimeout(1.0)
    
    print(f'{蓝色}[代理] 已启动，监听端口 {本地端口}{重置}')
    
    while True:
        try:
            data, 客户端地址 = 本地socket.recvfrom(65536)
            客户端IP = 客户端地址[0]
            
            if 攻击检测(客户端IP, 'NORMAL'):
                拦截攻击连接 += 1
                continue
            
            if data[0] == 0xA0:
                if 攻击检测(客户端IP, 'NACK'):
                    拦截攻击连接 += 1
                    拦截NACK += 1
                    continue
            
            if data[0] in [0x01, 0x05, 0x07]:
                攻击检测(客户端IP, 'HANDSHAKE')
            
            目标socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            目标socket.settimeout(2.0)
            
            try:
                目标socket.sendto(data, (目标主机, 目标端口))
                with 锁:
                    发送数据包 += 1
                
                while True:
                    try:
                        响应, _ = 目标socket.recvfrom(65536)
                        本地socket.sendto(响应, 客户端地址)
                        with 锁:
                            接收数据包 += 1
                    except socket.timeout:
                        break
            except Exception:
                pass
            finally:
                目标socket.close()
                
            time.sleep(0.01)
            
        except socket.timeout:
            continue
        except Exception:
            pass


def 防御线程(host, port, 线程ID):
    global 成功连接, 防御次数, 发送数据包, 接收数据包, 拦截NACK
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    
    while True:
        try:
            guid = random.getrandbits(64)
            
            pkt = 创建合法Ping包()
            sock.sendto(pkt, (host, port))
            with 锁:
                发送数据包 += 1
            
            try:
                r, _ = sock.recvfrom(2048)
                with 锁:
                    接收数据包 += 1
                
                if r[0] == 0x06:
                    pkt = 创建合法OpenConnectionRequest(host, port, guid)
                    sock.sendto(pkt, (host, port))
                    with 锁:
                        发送数据包 += 1
                    
                    try:
                        r, _ = sock.recvfrom(2048)
                        with 锁:
                            接收数据包 += 1
                        
                        if r[0] == 0x08:
                            pkt = 创建合法ConnectionRequest(guid)
                            sock.sendto(pkt, (host, port))
                            with 锁:
                                发送数据包 += 1
                            
                            for _ in range(30):
                                try:
                                    r, addr = sock.recvfrom(2048)
                                    with 锁:
                                        接收数据包 += 1
                                    
                                    if r[0] == 0xA0:
                                        with 锁:
                                            拦截NACK += 1
                                        continue
                                    
                                    if r[0] == 0x84 and len(r) >= 4:
                                        seq = struct.unpack('<I', r[1:4] + b'\x00')[0]
                                        ack = 创建合法ACK(seq)
                                        sock.sendto(ack, (host, port))
                                        with 锁:
                                            发送数据包 += 1
                                        
                                        if r[4] == 0x60 and len(r) > 14 and r[14] == 0x10:
                                            pkt = 创建合法NIC(host, port)
                                            sock.sendto(pkt, (host, port))
                                            with 锁:
                                                发送数据包 += 1
                                                成功连接 += 1
                                                防御次数 += 1
                                            颜色 = 获取状态颜色('在线')
                                            print(f'[线程-{线程ID}] 成功建立合法连接! 累计防御: {防御次数}')
                                            
                                            for _ in range(100):
                                                try:
                                                    r, _ = sock.recvfrom(2048)
                                                    with 锁:
                                                        接收数据包 += 1
                                                    
                                                    if r[0] == 0xA0:
                                                        with 锁:
                                                            拦截NACK += 1
                                                        continue
                                                    
                                                    if r[0] == 0x84 and len(r) >= 4:
                                                        seq = struct.unpack('<I', r[1:4] + b'\x00')[0]
                                                        ack = 创建合法ACK(seq)
                                                        sock.sendto(ack, (host, port))
                                                        with 锁:
                                                            发送数据包 += 1
                                                except socket.timeout:
                                                    pkt = 创建合法Ping包()
                                                    sock.sendto(pkt, (host, port))
                                                    with 锁:
                                                        发送数据包 += 1
                                                except Exception:
                                                    break
                                                time.sleep(0.05)
                                            break
                                except socket.timeout:
                                    break
                                except Exception:
                                    break
                    except socket.timeout:
                        pass
                    except Exception:
                        pass
            except socket.timeout:
                pass
            except Exception:
                pass
            
            time.sleep(0.1)
        
        except Exception:
            try:
                sock.close()
            except:
                pass
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            time.sleep(0.1)


def 状态检测线程(host, port):
    while True:
        检测服务器(host, port)
        清理过期连接()
        time.sleep(3)


def 统计线程():
    while True:
        time.sleep(2)
        with 锁:
            当前连接 = 成功连接
            当前防御 = 防御次数
            当前发送 = 发送数据包
            当前接收 = 接收数据包
            当前拦截 = 拦截NACK
            当前拦截连接 = 拦截攻击连接
            当前拦截握手 = 拦截握手攻击
            当前状态 = 服务器状态
        
        颜色 = 获取状态颜色(当前状态)
        print(f'[防御统计] 服务器状态: {颜色}{当前状态}{重置} | 成功连接: {当前连接} | 防御次数: {当前防御} | 发送: {当前发送} | 接收: {当前接收} | 拦截NACK: {黄色}{当前拦截}{重置} | 拦截连接: {红色}{当前拦截连接}{重置} | 拦截握手: {红色}{当前拦截握手}{重置}')


def run(host, port, 线程数=39, 代理端口=19133):
    开发者, QQ群 = _decode_meta()
    
    print('=' * 60)
    print('  NetGuard - NetEase Server Protection')
    print(f'  Version: {VERSION}')
    print('=' * 60)
    print(f'目标服务器: {host}:{port}')
    print(f'防御线程数: {线程数}')
    print(f'代理端口: {代理端口}')
    print('=' * 60)
    print('工具原理:')
    print('  针对sleekx_lock新锁服攻击:')
    print('  1. 发送0x01 UnconnectedPing获取服务器GUID')
    print('  2. 发送0x05 OpenConnectionRequest1')
    print('  3. 发送0x07 OpenConnectionRequest2')
    print('  4. 大量并发握手请求导致服务器资源耗尽')
    print('  本工具防御方式:')
    print('  1. 代理模式: 正常玩家通过代理连接服务器')
    print('  2. 攻击检测: 识别高频握手IP并拉黑')
    print('  3. 抢占槽位: 防御线程抢占连接槽位阻挡攻击者')
    print('  4. ACK确认: 发送ACK包帮助服务器清理数据队列')
    print('=' * 60)
    print('使用方式:')
    print('  1. 运行本工具')
    print('  2. 玩家连接代理端口(如19133)而非服务器端口')
    print('  3. 工具自动拦截攻击连接，允许正常玩家进入')
    print('=' * 60)
    print(f'{蓝色}{开发者}{重置}')
    print(f'{蓝色}QQ群: {QQ群}（有问题来这里问）{重置}')
    print('=' * 60)
    print('按 Ctrl+C 停止运行')
    print()

    print('正在检测服务器状态...')
    检测结果 = 检测服务器(host, port)
    颜色 = 获取状态颜色(检测结果)
    print(f'服务器状态: {颜色}{检测结果}{重置}')
    print()

    t = threading.Thread(target=代理转发线程, args=(代理端口, host, port), daemon=True)
    t.start()

    for i in range(线程数):
        t = threading.Thread(target=防御线程, args=(host, port, i), daemon=True)
        t.start()
        time.sleep(0.02)

    t = threading.Thread(target=状态检测线程, args=(host, port), daemon=True)
    t.start()

    统计线程()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print('\n\n正在停止保护...')
        return 0


NG_SECURITY_TOKEN = True

if __name__ == '__main__':
    print('=' * 60)
    print('  NetGuard - NetEase Server Protection')
    print(f'  Version: {VERSION}')
    print('=' * 60)
    print('正在验证脚本完整性...')
    
    _verify()
    开发者, QQ群 = _decode_meta()
    
    print(f'{绿色}脚本完整性校验通过!{重置}')
    print(f'{蓝色}{开发者}{重置}')
    print(f'{蓝色}QQ群: {QQ群}（有问题来这里问）{重置}')
    print('=' * 60)
    
    if len(sys.argv) >= 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        线程数 = int(sys.argv[3]) if len(sys.argv) >= 4 else 39
        代理端口 = int(sys.argv[4]) if len(sys.argv) >= 5 else 19133
        
        print(f"\n正在启动保护...")
        print(f"目标服务器: {host}:{port}")
        print(f"防御线程: {线程数}")
        print(f"代理端口: {代理端口}")
        sys.exit(run(host, port, 线程数, 代理端口))
    else:
        print()
        print('本工具的作用：')
        print('  当你的网易租赁服被sleekx_lock新锁服攻击时，')
        print('  本工具通过代理模式拦截攻击，允许正常玩家进入。')
        print()
        print('使用建议：')
        print('  1. 建议在服务器正常时就启动本工具')
        print('  2. 玩家连接代理端口而非服务器端口')
        print('  3. 工具会自动识别并拦截攻击连接')
        print()
        
        print("请输入目标服务器信息：")
        host = input("目标服务器IP: ").strip()
        port = int(input("目标服务器端口: ").strip())
        线程数 = int(input("防御线程数（默认39）: ").strip() or 39)
        代理端口 = int(input("代理端口（默认19133）: ").strip() or 19133)

        print(f"\n正在启动保护...")
        sys.exit(run(host, port, 线程数, 代理端口))