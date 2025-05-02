# Linux Security Dashboard

A comprehensive real-time security monitoring and visualization system for Linux environments. This dashboard provides system administrators with an intuitive web-based interface to monitor system security status, track authentication attempts, visualize security events, and manage firewall rules.

## Features

- **System Status Monitoring**: Real-time monitoring of critical system services and components
- **Firewall Status & Rules**: UFW (Uncomplicated Firewall) status tracking and rule visualization
- **Authentication Tracking**: Monitor failed login attempts, password failures, and session activities
- **Fail2ban Integration**: Track banned IPs and jail status
- **AppArmor Status**: Monitor AppArmor profiles and enforcement status
- **Disk Usage Visualization**: Track disk usage with interactive pie charts
- **Network Traffic Analysis**: Monitor network protocols and traffic patterns
- **Security Event Timeline**: Visualize security events over time
- **Backup Status Tracking**: Monitor system backup status and schedule
- **Auto-refresh Capability**: Dashboard automatically refreshes at configurable intervals
- **Systemd Integration**: Runs as a system service with scheduled updates

## Requirements

- Python 3.6+
- Linux system with:
  - UFW firewall
  - Fail2ban
  - AppArmor
  - Systemd
- Modern web browser for dashboard viewing

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/username/linux-security-dashboard.git
   cd linux-security-dashboard
   ```

2. Install required Python packages:
   ```bash
   pip install psutil matplotlib pandas numpy
   ```

3. Make the scripts executable:
   ```bash
   chmod +x security_dashboard.py
   chmod +x security_dashboard_startup.sh
   chmod +x security_dashboard_update.sh
   chmod +x install_systemd_timer.sh
   ```

4. Install the systemd service and timer:
   ```bash
   ./install_systemd_timer.sh
   ```

## Usage

### Manual Execution

Run the dashboard manually:
```bash
./security_dashboard.py
```

This will generate an HTML report and open it in your default web browser.

### Command Line Options

- `--update-only`: Update the dashboard without opening it in a browser
- `--refresh-interval <seconds>`: Set the auto-refresh interval (default: 300 seconds)
- `--no-refresh`: Disable auto-refresh

Example:
```bash
./security_dashboard.py --refresh-interval 60
```

### Systemd Service

The dashboard automatically runs as a systemd service that updates every 5 minutes:

- Check service status:
  ```bash
  systemctl status security-dashboard.service
  ```

- Check timer status:
  ```bash
  systemctl status security-dashboard.timer
  ```

- Manual service start:
  ```bash
  systemctl start security-dashboard.service
  ```

### Dashboard Access

The dashboard generates HTML reports in the `security_reports/` directory. The most recent report is opened automatically when running the script without the `--update-only` flag.

## Configuration

The dashboard configuration is managed through the Python script variables. Edit `security_dashboard.py` to customize:

- Chart colors and appearance
- Monitored services
- Report refresh rate
- Disk partitions to monitor
- Authentication log files location

## License

MIT License

Copyright (c) 2025 Philip S. Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

