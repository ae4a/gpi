# Glubokaya Paketnaya Inspektsiya
Simple DPI between two namespaces:
- root: tun1 10.0.0.1/24
- ns2: tun2 10.0.0.2/24

# Setting up namespaces
`sudo ip netns add ns2`
the rest will be done by `gpi`

# Some multipass lifehacks (macos)
## Fix multipass inet access(with vpn)
- find your vpn interface in `ifconfig` something like `utun5` ask ai
- find your multipass interface ip - something like `bridge0` or `bridge100`
- enable ip forwarding `sudo sysctl -w net.inet.ip.forwarding=1`
- add rule to send data to it from mp `echo "nat on <VPN_IF> from <MP_IP>/24 to any -> (<VPN_IF>)" | sudo pfctl -ef -`
- check that it is there `sudo pfctl -sn`
- restart mp `sudo launchctl kickstart -k system/com.canonical.multipassd`
- ready

- reset it: `sudo pfctl -F nat`
