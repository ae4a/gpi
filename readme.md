# Setting up namespaces
it will be 
- root tun1 10.0.0.1/24
- ns2 tun2 10.0.0.2/24



ip tuntap add dev tun0 mode tun
ip addr add 10.0.0.1/24 dev tun0
ip link set tun0 mtu 1600 up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -o <eth> -j MASQUERADE

ip netns exec ns2 ip tuntap add dev tun2 mode tun
ip netns exec ns2 ip addr add 10.0.0.2/24 dev tun2
ip netns exec ns2 ip link set tun2 mtu 1400 up
ip netns exec ns2 ip route add default dev tun2

mkdir -p /etc/netns/ns2
echo "nameserver 1.1.1.1" | tee /etc/netns/ns2/resolv.conf


# Fix multipass inet access(with vpn)

echo "nat on utun5 from 192.168.64.0/24 to any -> (utun5)" | sudo pfctl -ef -

or 
echo "nat on en0 from 192.168.64.0/24 to any -> (en0)" | sudo pfctl -ef -
