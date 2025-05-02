#!/bin/bash

# Make script executable
chmod +x /home/booboo/security_dashboard_update.sh

# Copy service and timer files to systemd directory
sudo cp /home/booboo/security-dashboard.service /etc/systemd/system/
sudo cp /home/booboo/security-dashboard.timer /etc/systemd/system/

# Reload systemd, enable and start the timer
sudo systemctl daemon-reload
sudo systemctl enable security-dashboard.timer
sudo systemctl start security-dashboard.timer

# Check status
echo "Timer status:"
sudo systemctl status security-dashboard.timer

echo -e "\nNext run times:"
sudo systemctl list-timers | grep security-dashboard

