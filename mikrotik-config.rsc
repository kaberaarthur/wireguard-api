
# RouterOS script created by wireguard-api
/interface wireguard
add name=wg-3002 private-key="eDytNt+J+lhCh9KBBtYYkXXHe0L+zlIeZ2FjKmFzpWA=" listen-port=0

/ip address
add address=10.0.0.3/32 interface=wg-3002

/interface wireguard peers
add interface=wg-3002 public-key="lcXH1Py3Fza9dqRnCEKRPqnHoe58wyeR+IOvYc/jmg8=" endpoint-address=157.245.170.185 endpoint-port=51820 persistent-keepalive=25 allowed-address=10.0.0.1/32

# Optional: route all traffic through the tunnel
# /ip route add dst-address=0.0.0.0/0 gateway=10.0.0.1
