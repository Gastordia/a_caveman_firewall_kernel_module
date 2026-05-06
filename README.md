# Caveman Firewall

kernel firewall for filtering ipv4, ipv6 and icmp
made it primarly to refresh my memory about linux kernel dev
also to block ipv6 traffic from scary evil isp when using a vpn

## Build
build with 
```bash
make
```

## Usage

block all incoming traffic with 
this blocks the traffic coming to your machine but you still can access services as your ipv4 traffic doesn't get filtered unless the ports=0 flag is specified
```bash
sudo insmod firewall.ko ipv4_param=1 icmp_param=1 ipv6_param=1
```
allow only outgoing https traffic
```bash
sudo insmod firewall.ko ipv4_param=1 ports=443 icmp_param=1 ipv6_param=1
```
allow multiple ports
```bash
sudo insmod firewall.ko ipv4_param=1 ports=22,80,443 icmp_param=0 ipv6_param=1
```
unload with 
```bash
sudo rmmod firewall
```
read logs with
```bash
sudo dmesg
```
