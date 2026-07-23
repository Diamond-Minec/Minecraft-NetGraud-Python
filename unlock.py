import socket
import struct
import random
import time
import sys
import threading

VERSION = 'v1.0 BETA'
MAGIC = b'\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78'

成功连接 = 0
防御次数 = 0
发送数据包 = 0
接收数据包 = 0
锁 = threading.Lock()


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


def 防御线程(host, port, 线程ID):
    global 成功连接, 防御次数, 发送数据包, 接收数据包
    
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
                            
                            for _ in range(20):
                                try:
                                    r, addr = sock.recvfrom(2048)
                                    with 锁:
                                        接收数据包 += 1
                                    
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
                                            print(f'[线程-{线程ID}] 成功建立合法连接! 累计防御: {防御次数}')
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
            
            time.sleep(0.2)
        
        except Exception:
            try:
                sock.close()
            except:
                pass
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            time.sleep(0.5)


def 统计线程():
    while True:
        time.sleep(2)
        with 锁:
            当前连接 = 成功连接
            当前防御 = 防御次数
            当前发送 = 发送数据包
            当前接收 = 接收数据包
        
        print(f'[防御统计] 成功连接: {当前连接} | 防御次数: {当前防御} | 发送: {当前发送} | 接收: {当前接收}')


def run(host, port, 线程数=20):
    print('=' * 60)
    print('  NetGuard - NetEase Server Protection')
    print(f'  Version: {VERSION}')
    print('=' * 60)
    print(f'目标服务器: {host}:{port}')
    print(f'防御线程数: {线程数}')
    print('=' * 60)
    print('工具原理:')
    print('  锁服攻击是通过发送恶意NACK包拒绝所有数据序列，')
    print('  让服务器不断重传导致卡顿。')
    print('  本工具使用标准RakNet协议建立合法连接，')
    print('  发送合法ACK确认包，帮助服务器清理数据队列。')
    print('=' * 60)
    print('合法数据包类型:')
    print('  0x05 Ping - 探测服务器')
    print('  0x07 OpenConnectionRequest - 打开连接请求')
    print('  0x09 ConnectionRequest - 连接请求')
    print('  0xC0 ACK - 确认收到数据')
    print('=' * 60)
    print('沧蓝工坊开发（群主Diamond）')
    print('QQ群: 956766495（有问题来这里问）')
    print('=' * 60)
    print('按 Ctrl+C 停止运行')
    print()

    for i in range(线程数):
        t = threading.Thread(target=防御线程, args=(host, port, i), daemon=True)
        t.start()
        time.sleep(0.05)

    统计线程()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print('\n\n正在停止保护...')
        return 0


if __name__ == '__main__':
    print('=' * 60)
    print('  NetGuard - NetEase Server Protection')
    print(f'  Version: {VERSION}')
    print('  沧蓝工坊开发（群主Diamond）')
    print('  QQ群: 956766495（有问题来这里问）')
    print('=' * 60)
    print()
    print('本工具的作用：')
    print('  当你的网易租赁服被别人恶意攻击锁服时，')
    print('  本工具会使用标准RakNet协议建立合法连接，')
    print('  帮助服务器恢复正常运行。')
    print()
    print('使用建议：')
    print('  1. 建议在服务器正常时就启动本工具')
    print('  2. 线程数建议设置为服务器最大玩家数')
    print('  3. 启动后保持运行，即使被攻击也能自动防御')
    print()
    
    print("请输入目标服务器信息：")
    host = input("目标服务器IP: ").strip()
    port = int(input("目标服务器端口: ").strip())
    线程数 = int(input("防御线程数（默认20）: ").strip() or 20)

    print(f"\n正在启动保护...")
    sys.exit(run(host, port, 线程数))