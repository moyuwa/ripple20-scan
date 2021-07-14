#!/usr/bin/python
# coding=utf-8
# python 2.7

import os, logging
import threading, time
import ipaddress
from scapy.all import *


class sc_ripper20():
    def __init__(self):
        self._ICMP_MS_SYNC_REQ_TYPE = 0xa5  # 发送
        self._ICMP_MS_SYNC_RSP_TYPE = 0xa6  # 响应
        self._time_out = 2  # 如果是外网可以加大延时
        self._threads = 16  # 线程数

    def com_ips(self, net_local=u''):
        net = ipaddress.ip_network(net_local, strict=False)
        uips = []
        for ip in net.hosts():
            uips.append(ip.compressed)
        return uips

    def scan_ip_rippler20(self, ip=u''):
        p = IP(dst=ip) / ICMP(type=self._ICMP_MS_SYNC_REQ_TYPE, code=0)  # 直接发包探测
        ans, unans = sr(p, timeout=self._time_out)  #
        if not ans:
            logging.info(u"%s ICMP无响应" % ip)
        for req, resp in ans:
            if ICMP in resp and resp[ICMP].type == self._ICMP_MS_SYNC_RSP_TYPE:
                logging.info(u"%s 有treck堆栈" % ip)
            else:
                logging.info(u"%s 无treck堆栈" % ip)
        self._threads += 1

    def net_seg(self, net_seg=u''):
        for ip in self.com_ips(net_seg):
            t1 = threading.Thread(target=self.scan_ip_rippler20, args=[ip, ])
            t1.start()
            self._threads -= 1
            while self._threads < 1:
                time.sleep(self._time_out)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)s %(module)s/%(funcName)s:%(message)s',
                        datefmt='%Y-%m-%d-%X',
						filename=os.getcwd() + '/rippler20.log', 
						filemode='a')
    logging.info(u'rippler20漏洞 Treck网络栈发现')

    net_seg = u'10.10.25.0/24'  # 填写ip或网段 unicode格式

    s = sc_ripper20()
    if net_seg.find('/') != -1:
        s.net_seg(net_seg)
    else:
        s.scan_ip_rippler20(net_seg)  # 单IP扫描
