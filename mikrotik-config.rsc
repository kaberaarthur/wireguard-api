
# RouterOS script created by wireguard-api
/interface wireguard
add name=wg-3001 private-key="qJk2rMLAZcUKK95s935xTct86uk5U2OeAY2RyNL7VWo=" listen-port=0

/ip address
add address=10.0.0.2/32 interface=wg-3001

# add server as peer
/interface wireguard peers
add interface=wg-3001 public-key="lcXH1Py3Fza9dqRnCEKRPqnHoe58wyeR+IOvYc/jmg8=" endpoint-address=157.245.170.185 endpoint-port=51820 persistent-keepalive=25 allowed-address=10.0.0.1/32

# Optional: route all traffic through the tunnel
# /ip route add dst-address=0.0.0.0/0 gateway=10.0.0.1
