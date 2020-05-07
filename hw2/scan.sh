#!/bin/bash
for ip in 192.168.159.{1..254}; do
  sudo arp -d $ip > /dev/null 2>&1
  ping -c 5 $ip > /dev/null 2>&1 &
done

# 等待所有背景的 Ping 結束
wait

# 輸出 ARP table
arp -a
