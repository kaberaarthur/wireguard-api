cat > setup.sh << 'EOF'
#!/bin/bash
# setup.sh - Initial server setup script

set -e

echo "Setting up WireGuard server..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y wireguard wireguard-tools iptables-persistent nodejs npm sqlite3

# Generate server keys if they don't exist
if [ ! -f /etc/wireguard/privatekey ]; then
    echo "Generating WireGuard server keys..."
    wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
    sudo chmod 600 /etc/wireguard/privatekey
    sudo chmod 644 /etc/wireguard/publickey
fi

# Create WireGuard configuration directly
echo "Creating WireGuard configuration..."
sudo tee /etc/wireguard/wg0.conf > /dev/null << EOF2
# /etc/wireguard/wg0.conf
# Server WireGuard configuration

[Interface]
PrivateKey = $(sudo cat /etc/wireguard/privatekey)
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = false

# Enable packet forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE

# Peers will be added dynamically by the API
EOF2

# Enable and start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Install Node.js dependencies
npm install express body-parser sqlite3 dotenv

# Create systemd service for the API
sudo tee /etc/systemd/system/wireguard-api.service > /dev/null << EOF3
[Unit]
Description=WireGuard API Service
After=network.target wg-quick@wg0.service

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/node app.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF3

# Enable the service
sudo systemctl daemon-reload
sudo systemctl enable wireguard-api

echo "Setup complete!"
echo "Server public key: $(sudo cat /etc/wireguard/publickey)"
echo "Update your .env file with this public key"
echo "Start the API with: sudo systemctl start wireguard-api"
echo "Check logs with: sudo journalctl -u wireguard-api -f"
EOF