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

# Create WireGuard configuration
sudo cp wg0.conf /etc/wireguard/wg0.conf
sudo sed -i "s/YOUR_SERVER_PRIVATE_KEY_HERE/$(sudo cat /etc/wireguard/privatekey)/" /etc/wireguard/wg0.conf

# Enable and start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0

# Install Node.js dependencies
npm install express body-parser sqlite3 dotenv

# Create systemd service for the API
sudo tee /etc/systemd/system/wireguard-api.service > /dev/null <<EOF
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
EOF

# Enable the service
sudo systemctl daemon-reload
sudo systemctl enable wireguard-api

echo "Setup complete!"
echo "Server public key: $(sudo cat /etc/wireguard/publickey)"
echo "Update your .env file with this public key"
echo "Start the API with: sudo systemctl start wireguard-api"
echo "Check logs with: sudo journalctl -u wireguard-api -f"