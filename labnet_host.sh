sudo ip tuntap add dev tap0 mode tap user $USER
sudo ip link set dev tap0 address 1a:70:fd:73:8e:e9
sudo ip addr add 10.0.2.1/24 dev tap0
sudo ip link set tap0 up

sudo ip addr show tap0

sudo sysctl -w net.ipv4.ip_forward=1
sudo cat /proc/sys/net/ipv4/ip_forward

sudo ip route show default

sudo iptables -A FORWARD -i tap0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o tap0 \
    -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -t nat -A POSTROUTING \
    -s 10.0.2.0/24 -o eth0 -j MASQUERADE