#!/bin/bash

# Copy service file to systemd directory
sudo cp /home/booboo/linux-security-dashboard/linux-security-dashboard-ui.service /etc/systemd/system/

# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable linux-security-dashboard-ui.service
sudo systemctl start linux-security-dashboard-ui.service

# Check status
echo "Service status:"
sudo systemctl status linux-security-dashboard-ui.service

echo -e "\nDashboard UI service has been installed and started."
echo "It will automatically start on system boot."

