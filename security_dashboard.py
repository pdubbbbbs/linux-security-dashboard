#!/usr/bin/env python3
import subprocess
import os
import time
import datetime
import webbrowser
import socket
import pwd
import sys
import argparse
import json
import re
import psutil
import random
from collections import defaultdict
import shutil

def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, shell=True, check=False, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error running command: {e}"

def get_ufw_status():
    """Get UFW status and rules"""
    status = run_command("sudo ufw status verbose")
    return status

def get_fail2ban_status():
    """Get Fail2ban status and recent bans"""
    status = run_command("sudo fail2ban-client status")
    jails = []
    
    # Extract jail names
    for line in status.splitlines():
        if "Jail list:" in line:
            jail_list = line.split("Jail list:")[1].strip()
            jails = [jail.strip() for jail in jail_list.split(",")]
    
    # Get detailed status for each jail
    detailed_status = status + "\n\n"
    for jail in jails:
        jail_status = run_command(f"sudo fail2ban-client status {jail}")
        detailed_status += f"\n{jail_status}\n"
    
    return detailed_status

def get_apparmor_status():
    """Get AppArmor status"""
    status = run_command("sudo aa-status")
    return status

def get_recent_auth_attempts():
    """Get recent authentication attempts"""
    auth_log = run_command("sudo grep 'authentication failure\|Failed password\|session opened\|session closed' /var/log/auth.log | tail -20")
    return auth_log

def get_system_security_status():
    """Get general system security information"""
    hostname = socket.gethostname()
    uptime = run_command("uptime")
    disk_space = run_command("df -h")
    last_logins = run_command("last -n 5")
    current_connections = run_command("netstat -tuln | grep LISTEN")
    
    return {
        "hostname": hostname,
        "uptime": uptime,
        "disk_space": disk_space,
        "last_logins": last_logins,
        "current_connections": current_connections
    }

def get_backup_status():
    """Get recent backup information"""
    backup_dir = "/var/backups/system"
    backup_files = run_command(f"sudo ls -la {backup_dir} | tail -10")
    return backup_files

def get_system_metrics():
    """Get system resource metrics for charts"""
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
    
    # Memory usage
    memory = psutil.virtual_memory()
    memory_data = {
        "total": memory.total / (1024 * 1024 * 1024),  # Convert to GB
        "available": memory.available / (1024 * 1024 * 1024),
        "used": (memory.total - memory.available) / (1024 * 1024 * 1024),
        "percent": memory.percent
    }
    
    # Disk usage
    disk_usage = []
    for partition in psutil.disk_partitions():
        if os.name == 'nt' and ('cdrom' in partition.opts or partition.fstype == ''):
            # Skip CD-ROM drives on Windows
            continue
        usage = psutil.disk_usage(partition.mountpoint)
        disk_usage.append({
            "mountpoint": partition.mountpoint,
            "total": usage.total / (1024 * 1024 * 1024),  # Convert to GB
            "used": usage.used / (1024 * 1024 * 1024),
            "free": usage.free / (1024 * 1024 * 1024),
            "percent": usage.percent
        })
    
    # Network stats
    network = psutil.net_io_counters()
    network_data = {
        "bytes_sent": network.bytes_sent / (1024 * 1024),  # Convert to MB
        "bytes_received": network.bytes_recv / (1024 * 1024),
        "packets_sent": network.packets_sent,
        "packets_received": network.packets_recv
    }
    
    return {
        "cpu": cpu_percent,
        "memory": memory_data,
        "disk": disk_usage,
        "network": network_data
    }

def parse_auth_log():
    """Parse auth.log for visualization data"""
    auth_log = run_command("sudo grep 'authentication failure\\|Failed password\\|session opened\\|session closed' /var/log/auth.log")
    
    # Count events by type
    event_counts = {
        "authentication_failure": 0,
        "failed_password": 0,
        "session_opened": 0,
        "session_closed": 0
    }
    
    ip_addresses = defaultdict(int)
    users = defaultdict(int)
    
    for line in auth_log.splitlines():
        if "authentication failure" in line:
            event_counts["authentication_failure"] += 1
            
            # Try to extract user
            user_match = re.search(r'user=([^\s]+)', line)
            if user_match:
                users[user_match.group(1)] += 1
                
            # Try to extract IP
            ip_match = re.search(r'rhost=([0-9\.]+)', line)
            if ip_match:
                ip_addresses[ip_match.group(1)] += 1
                
        elif "Failed password" in line:
            event_counts["failed_password"] += 1
            
            # Try to extract user
            user_match = re.search(r'for ([^\s]+)', line)
            if user_match:
                users[user_match.group(1)] += 1
                
            # Try to extract IP
            ip_match = re.search(r'from ([0-9\.]+)', line)
            if ip_match:
                ip_addresses[ip_match.group(1)] += 1
                
        elif "session opened" in line:
            event_counts["session_opened"] += 1
        elif "session closed" in line:
            event_counts["session_closed"] += 1
    
    return {
        "event_counts": event_counts,
        "ip_addresses": dict(ip_addresses),
        "users": dict(users)
    }

def get_firewall_stats():
    """Parse UFW logs for visualization"""
    ufw_log = run_command("sudo grep 'UFW BLOCK' /var/log/syslog | tail -100")
    
    ports = defaultdict(int)
    protocols = defaultdict(int)
    ip_addresses = defaultdict(int)
    
    for line in ufw_log.splitlines():
        # Extract ports
        dst_port_match = re.search(r'DPT=([0-9]+)', line)
        if dst_port_match:
            ports[dst_port_match.group(1)] += 1
            
        # Extract protocols
        proto_match = re.search(r'PROTO=([A-Za-z]+)', line)
        if proto_match:
            protocols[proto_match.group(1)] += 1
            
        # Extract IPs
        src_ip_match = re.search(r'SRC=([0-9\.]+)', line)
        if src_ip_match:
            ip_addresses[src_ip_match.group(1)] += 1
    
    return {
        "ports": dict(ports),
        "protocols": dict(protocols),
        "ip_addresses": dict(ip_addresses)
    }

def update_historical_data(metrics):
    """Store and manage historical data for trend analysis"""
    history_file = os.path.join(os.path.expanduser("~"), "security_reports", "history.json")
    history_dir = os.path.dirname(history_file)
    os.makedirs(history_dir, exist_ok=True)
    
    # Current timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Initialize or load history
    if os.path.exists(history_file):
        with open(history_file, 'r') as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = {"cpu": [], "memory": [], "network": [], "events": [], "timestamps": []}
    else:
        history = {"cpu": [], "memory": [], "network": [], "events": [], "timestamps": []}
    
    # Limit history to last 50 data points
    max_history = 50
    if len(history["timestamps"]) >= max_history:
        for key in history:
            history[key] = history[key][-max_history+1:]
    
    # Add current metrics
    history["timestamps"].append(timestamp)
    
    # CPU average
    avg_cpu = sum(metrics["cpu"]) / len(metrics["cpu"]) if metrics["cpu"] else 0
    history["cpu"].append(avg_cpu)
    
    # Memory
    history["memory"].append(metrics["memory"]["percent"])
    
    # Network (cumulative, we'll calculate rates in JS)
    history["network"].append({
        "sent": metrics["network"]["bytes_sent"],
        "received": metrics["network"]["bytes_received"]
    })
    
    # Parse auth log
    auth_data = parse_auth_log()
    history["events"].append({
        "auth_failures": auth_data["event_counts"]["authentication_failure"],
        "failed_passwords": auth_data["event_counts"]["failed_password"],
        "sessions_opened": auth_data["event_counts"]["session_opened"],
        "sessions_closed": auth_data["event_counts"]["session_closed"]
    })
    
    # Save history
    with open(history_file, 'w') as f:
        json.dump(history, f)
    
    return history

def generate_html_report(auto_refresh=True, refresh_interval=300):
    """Generate HTML report with all security information
    
    Args:
        auto_refresh (bool): Whether to automatically refresh the page
        refresh_interval (int): Refresh interval in seconds
    """
    print("Starting to generate HTML report...")
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname = socket.gethostname()
    username = pwd.getpwuid(os.getuid()).pw_name
    
    # Get security information
    ufw_status = get_ufw_status()
    fail2ban_status = get_fail2ban_status()
    apparmor_status = get_apparmor_status()
    auth_attempts = get_recent_auth_attempts()
    system_status = get_system_security_status()
    backup_status = get_backup_status()
    
    # Get metrics for charts
    metrics = get_system_metrics()
    
    # Update historical data
    history = update_historical_data(metrics)
    
    # Get additional data for charts
    auth_data = parse_auth_log()
    firewall_stats = get_firewall_stats()
    
    # Create report directory if it doesn't exist
    report_dir = os.path.join(os.path.expanduser("~"), "security_reports")
    os.makedirs(report_dir, exist_ok=True)
    
    # Create HTML file
    report_path = os.path.join(report_dir, "security_dashboard.html")
    
    # Generate HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    {"<meta http-equiv='refresh' content='" + str(refresh_interval) + "'>" if auto_refresh else ""}
    <title>Security Dashboard - {hostname}</title>
    <!-- Chart.js library for visualization -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@3.7.1/dist/chart.min.js"></script>
    <!-- Chart.js 3D plugin -->
    <script src="https://cdn.jsdelivr.net/npm/chartjs-plugin-datalabels@2.0.0"></script>
    <!-- ChartJS 3D effects -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js-plugin-3d@2.1.0/dist/chart.js-plugin-3d.min.js"></script>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #4361ee;
            --secondary-color: #3a0ca3;
            --accent-color: #7209b7;
            --success-color: #4cc9f0;
            --warning-color: #f72585;
            --info-color: #4895ef;
            --dark-color: #1e293b;
            --light-color: #f8f9fa;
            --card-shadow: 0 10px 20px rgba(0, 0, 0, 0.15);
            --text-primary: #334155;
            --text-secondary: #64748b;
        }}
        
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        
        body {{
            font-family: 'Poppins', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #f5f7fa 0%, #e4e7eb 100%);
            color: var(--text-primary);
            min-height: 100vh;
            font-size: 16px;
        }}
        
        .container {{
            width: 100%;
            min-height: 100vh;
            background-color: rgba(255, 255, 255, 0.95);
            padding: 1.5rem;
            box-shadow: var(--card-shadow);
            overflow-x: hidden;
        }}
        
        .dashboard-header {{
            background: linear-gradient(90deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 1.5rem 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            box-shadow: var(--card-shadow);
        }}
        
        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .live-timestamp {{
            text-align: right;
            font-family: 'Poppins', sans-serif;
            min-width: 180px;
        }}
        
        .live-timestamp .time {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
            letter-spacing: 1px;
        }}
        
        .live-timestamp .date {{
            font-size: 1rem;
            opacity: 0.9;
        }}
        
        h1 {{
            font-weight: 700;
            margin-bottom: 0.5rem;
            font-size: 2.5rem;
            letter-spacing: -0.5px;
        }}
        
        h2 {{
            color: var(--primary-color);
            margin-top: 2rem;
            margin-bottom: 1rem;
            font-weight: 600;
            font-size: 1.8rem;
            position: relative;
            padding-left: 1rem;
        }}
        
        h2:before {{
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 5px;
            background: linear-gradient(to bottom, var(--primary-color), var(--secondary-color));
            border-radius: 20px;
        }}
        
        h3 {{
            color: var(--dark-color);
            margin: 1rem 0;
            font-weight: 500;
            font-size: 1.2rem;
        }}
        
        pre {{
            background-color: var(--dark-color);
            color: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            white-space: pre-wrap;
            font-size: 0.9rem;
            box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
         }}
        
        .grid-container {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .card {{
            margin-bottom: 1.5rem;
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s ease;
            box-shadow: var(--card-shadow);
            border: none;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.2);
        }}
        
        .card-header {{
            background: linear-gradient(90deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            color: white;
            padding: 1rem 1.5rem;
            margin: -1.5rem -1.5rem 1.5rem -1.5rem;
            border-radius: 12px 12px 0 0;
            font-weight: 600;
            font-size: 1.1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .timestamp {{
            text-align: right;
            font-style: italic;
            color: var(--text-secondary);
            margin-top: 2rem;
            padding: 1rem;
            background-color: rgba(0, 0, 0, 0.03);
            border-radius: 8px;
        }}
        
        .status-error {{
            color: #ef4444;
            font-weight: 600;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 1rem 0;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
        }}
        
        table, th, td {{
            border: none;
        }}
        
        th, td {{
            padding: 1rem;
            text-align: left;
        }}
        
        th {{
            background: linear-gradient(90deg, var(--primary-color) 0%, var(--info-color) 100%);
            color: white;
            font-weight: 500;
        }}
        
        tr:nth-child(even) {{
            background-color: rgba(0, 0, 0, 0.02);
        }}
        
        .chart-container {{
            position: relative;
            height: 300px;
            width: 100%;
            padding: 1rem;
        }}
        
        .flex-wrap {{
            display: flex;
            flex-wrap: wrap;
            gap: 1.5rem;
        }}
        
        .flex-item {{
            flex: 1 1 300px;
            min-width: 0;
        }}
        
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 50px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .badge-primary {{
            background-color: var(--primary-color);
            color: white;
        }}
        
        .badge-warning {{
            background-color: var(--warning-color);
            color: white;
        }}
        
        .badge-info {{
            background-color: var(--info-color);
            color: white;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}
            
            h1 {{
                font-size: 1.8rem;
            }}
            
            h2 {{
                font-size: 1.5rem;
            }}
            
            .card {{
                padding: 1rem;
            }}
            
            .card-header {{
                padding: 0.75rem 1rem;
                margin: -1rem -1rem 1rem -1rem;
            }}
            
            .header-content {{
                flex-direction: column;
                align-items: flex-start;
            }}
            
            .live-timestamp {{
                margin-top: 1rem;
                text-align: left;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="dashboard-header">
            <div class="header-content">
                <div>
                    <h1>Security Dashboard - {hostname}</h1>
                    <p>Logged in as: <strong>{username}</strong></p>
                </div>
                <div class="live-timestamp">
                    <div class="time" id="currentTime">00:00:00</div>
                    <div class="date" id="currentDate">Loading...</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">System Status</div>
            <h3>Hostname: {hostname}</h3>
            <h3>Uptime</h3>
            <pre>{system_status["uptime"]}</pre>
            
            <h3>Disk Space</h3>
            <pre>{system_status["disk_space"]}</pre>
            
            <h3>Recent Logins</h3>
            <pre>{system_status["last_logins"]}</pre>
            
            <h3>Current Network Connections</h3>
            <pre>{system_status["current_connections"]}</pre>
        </div>
        
        <div class="card">
            <div class="card-header">UFW Firewall Status</div>
            <pre>{ufw_status}</pre>
        </div>
        
        <div class="card">
            <div class="card-header">Fail2ban Status</div>
            <pre>{fail2ban_status}</pre>
        </div>
        
        <div class="card">
            <div class="card-header">AppArmor Status</div>
            <pre>{apparmor_status}</pre>
        </div>
        
        <div class="card">
            <div class="card-header">Recent Authentication Attempts</div>
            <pre>{auth_attempts}</pre>
        </div>
        
        <div class="card">
            <div class="card-header">Backup Status</div>
            <pre>{backup_status}</pre>
        </div>
        
        <div class="timestamp">
            Dashboard data updated at: {timestamp}
            {"<br><small>(Data refreshes every " + str(refresh_interval) + " seconds)</small>" if auto_refresh else ""}
        </div>
        
        <!-- Charts Section -->
        <h2>Security Visualizations</h2>
        
        <div class="card">
            <div class="card-header">System Resource Usage</div>
            <div style="display: flex; flex-wrap: wrap;">
                <div style="width: 50%; min-width: 300px;">
                    <h3>CPU Usage</h3>
                    <canvas id="cpuChart" width="400" height="200"></canvas>
                </div>
                <div style="width: 50%; min-width: 300px;">
                    <h3>Memory Usage</h3>
                    <canvas id="memoryChart" width="400" height="200"></canvas>
                </div>
            </div>
            <div style="display: flex; flex-wrap: wrap; margin-top: 20px;">
                <div style="width: 50%; min-width: 300px;">
                    <h3>Network Activity</h3>
                    <canvas id="networkChart" width="400" height="200"></canvas>
                </div>
                <div style="width: 50%; min-width: 300px;">
                    <h3>Security Events History</h3>
                    <canvas id="eventsChart" width="400" height="200"></canvas>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">Disk Usage</div>
            <div style="display: flex; flex-wrap: wrap;">
                """

    # Add disk chart sections 
    for i, disk in enumerate(metrics['disk']):
        html_content += f"""
                    <div style="width: 50%; min-width: 300px;">
                        <h3>{disk['mountpoint']}</h3>
                        <canvas id="diskChart{i}" width="400" height="400"></canvas>
                    </div>
                """

    html_content += """
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">Security Events</div>
            <div style="display: flex; flex-wrap: wrap;">
                <div style="width: 50%; min-width: 300px;">
                    <h3>Authentication Events</h3>
                    <canvas id="authEventsChart" width="400" height="400"></canvas>
                </div>
                <div style="width: 50%; min-width: 300px;">
                    <h3>Failed Login Attempts by User</h3>
                    <canvas id="usersChart" width="400" height="400"></canvas>
                </div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">Firewall Statistics</div>
            <div style="display: flex; flex-wrap: wrap;">
                <div style="width: 50%; min-width: 300px;">
                    <h3>Blocked Ports</h3>
                    <canvas id="portsChart" width="400" height="300"></canvas>
                </div>
                <div style="width: 50%; min-width: 300px;">
                    <h3>Blocked Protocols</h3>
                    <canvas id="protocolsChart" width="400" height="300"></canvas>
                </div>
            </div>
        </div>
    </div>

    <!-- JavaScript for Charts -->
    <script>
        // Chart.js Configuration for 3D effect
        Chart.register(ChartDataLabels);

        // Live Clock Functionality
        function updateClock() {
            const now = new Date();
            
            // Update time with seconds
            const hours = now.getHours().toString().padStart(2, '0');
            const minutes = now.getMinutes().toString().padStart(2, '0');
            const seconds = now.getSeconds().toString().padStart(2, '0');
            document.getElementById('currentTime').textContent = `${hours}:${minutes}:${seconds}`;
            
            // Update date
            const options = { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' };
            document.getElementById('currentDate').textContent = now.toLocaleDateString('en-US', options);
        }
        
        // Update clock immediately and then every second
        updateClock();
        setInterval(updateClock, 1000);
        
        // Color palette
        const colors = [
            'rgba(54, 162, 235, 0.8)',
            'rgba(255, 99, 132, 0.8)',
            'rgba(75, 192, 192, 0.8)',
            'rgba(255, 159, 64, 0.8)',
            'rgba(153, 102, 255, 0.8)',
            'rgba(255, 205, 86, 0.8)',
            'rgba(201, 203, 207, 0.8)',
            'rgba(255, 99, 71, 0.8)',
            'rgba(60, 179, 113, 0.8)'
        ];
        
        // Format numbers
        function formatBytes(bytes, decimals = 2) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
        }
        
        // Historical Data
        const historyData = {json.dumps(history)};
        
        // CPU Chart
        const cpuCtx = document.getElementById('cpuChart').getContext('2d');
        const cpuChart = new Chart(cpuCtx, {
            type: 'line',
            data: {
                labels: historyData.timestamps,
                datasets: [{
                    label: 'CPU Usage %',
                    data: historyData.cpu,
                    borderColor: colors[0],
                    backgroundColor: colors[0].replace('0.8', '0.2'),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'CPU Usage History'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + '%';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Usage %'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                }
            }
        });
        
        // Memory Chart
        const memoryCtx = document.getElementById('memoryChart').getContext('2d');
        const memoryChart = new Chart(memoryCtx, {
            type: 'line',
            data: {
                labels: historyData.timestamps,
                datasets: [{
                    label: 'Memory Usage %',
                    data: historyData.memory,
                    borderColor: colors[1],
                    backgroundColor: colors[1].replace('0.8', '0.2'),
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Memory Usage History'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + '%';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: 'Usage %'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                }
            }
        });
        
        // Network Chart
        const networkCtx = document.getElementById('networkChart').getContext('2d');
        
        // Calculate network rate
        const networkRateReceived = [];
        const networkRateSent = [];
        
        for (let i = 1; i < historyData.network.length; i++) {
            const timeDiff = new Date(historyData.timestamps[i]) - new Date(historyData.timestamps[i-1]);
            const diffSeconds = timeDiff / 1000;
            
            const receivedDiff = historyData.network[i].received - historyData.network[i-1].received;
            const sentDiff = historyData.network[i].sent - historyData.network[i-1].sent;
            
            networkRateReceived.push(receivedDiff / diffSeconds);
            networkRateSent.push(sentDiff / diffSeconds);
        }
        
        const networkLabels = historyData.timestamps.slice(1);
        
        const networkChart = new Chart(networkCtx, {
            type: 'line',
            data: {
                labels: networkLabels,
                datasets: [
                    {
                        label: 'Received MB/s',
                        data: networkRateReceived,
                        borderColor: colors[2],
                        backgroundColor: colors[2].replace('0.8', '0.2'),
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Sent MB/s',
                        data: networkRateSent,
                        borderColor: colors[3],
                        backgroundColor: colors[3].replace('0.8', '0.2'),
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Network Activity'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return context.dataset.label + ': ' + context.parsed.y.toFixed(2) + ' MB/s';
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        title: {
                            display: true,
                            text: 'MB/s'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                }
            }
        });
        
        // Security Events Chart
        const eventsCtx = document.getElementById('eventsChart').getContext('2d');
        
        // Prepare data
        const authFailures = historyData.events.map(event => event.auth_failures);
        const failedPasswords = historyData.events.map(event => event.failed_passwords);
        const sessionsOpened = historyData.events.map(event => event.sessions_opened);
        
        const eventsChart = new Chart(eventsCtx, {
            type: 'line',
            data: {
                labels: historyData.timestamps,
                datasets: [
                    {
                        label: 'Authentication Failures',
                        data: authFailures,
                        borderColor: colors[0],
                        backgroundColor: colors[0].replace('0.8', '0.2'),
                        borderWidth: 2,
                        fill: false
                    },
                    {
                        label: 'Failed Passwords',
                        data: failedPasswords,
                        borderColor: colors[1],
                        backgroundColor: colors[1].replace('0.8', '0.2'),
                        borderWidth: 2,
                        fill: false
                    },
                    {
                        label: 'Sessions Opened',
                        data: sessionsOpened,
                        borderColor: colors[2],
                        backgroundColor: colors[2].replace('0.8', '0.2'),
                        borderWidth: 2,
                        fill: false
                    }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Security Events History'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Count'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Time'
                        }
                    }
                }
            }
        });
        
        // Disk Usage Charts - 3D Pie Charts
        // Generate disk charts JavaScript
        const diskData = {json.dumps(metrics["disk"])};
        
        // Create a disk chart for each disk
        for (let i = 0; i < diskData.length; i++) {
            const disk = diskData[i];
            const diskCtx = document.getElementById(`diskChart${i}`).getContext('2d');
            
            const diskChart = new Chart(diskCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Used', 'Free'],
                    datasets: [{
                        data: [disk.used, disk.free],
                        backgroundColor: [colors[1], colors[2]],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'right',
                        },
                        title: {
                            display: true,
                            text: `Disk Usage: ${disk.mountpoint}`
                        },
                        datalabels: {
                            formatter: (value, ctx) => {
                                let sum = disk.total;
                                let percentage = (value*100 / sum).toFixed(1)+"%";
                                return percentage;
                            },
                            color: '#fff',
                            font: {
                                weight: 'bold',
                                size: 12
                            }
                        }
                    }
                }
            });
        }
        
        // Authentication Events Pie Chart
        const authEventsData = {json.dumps(auth_data)};
        const authEventsCtx = document.getElementById('authEventsChart').getContext('2d');
        
        const authEventsChart = new Chart(authEventsCtx, {
            type: 'pie',
            data: {
                labels: ['Auth Failures', 'Failed Passwords', 'Sessions Opened', 'Sessions Closed'],
                datasets: [{
                    data: [
                        authEventsData.event_counts.authentication_failure,
                        authEventsData.event_counts.failed_password,
                        authEventsData.event_counts.session_opened,
                        authEventsData.event_counts.session_closed
                    ],
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Authentication Events'
                    },
                    datalabels: {
                        formatter: (value, ctx) => {
                            let sum = 0;
                            let dataArr = ctx.chart.data.datasets[0].data;
                            dataArr.map(data => {
                                sum += data;
                            });
                            let percentage = (value*100 / sum).toFixed(1)+"%";
                            return percentage;
                        },
                        color: '#fff',
                        font: {
                            weight: 'bold',
                            size: 12
                        }
                    }
                }
            }
        });
        
        // Failed Login Attempts by User
        const usersCtx = document.getElementById('usersChart').getContext('2d');
        
        // Get top 5 users
        const userEntries = Object.entries(authEventsData.users);
        userEntries.sort((a, b) => b[1] - a[1]);
        const topUsers = userEntries.slice(0, 5);
        
        const usersChart = new Chart(usersCtx, {
            type: 'pie',
            data: {
                labels: topUsers.map(entry => entry[0]),
                datasets: [{
                    data: topUsers.map(entry => entry[1]),
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Failed Login Attempts by User (Top 5)'
                    },
                    datalabels: {
                        formatter: (value, ctx) => {
                            let sum = 0;
                            let dataArr = ctx.chart.data.datasets[0].data;
                            dataArr.map(data => {
                                sum += data;
                            });
                            let percentage = (value*100 / sum).toFixed(1)+"%";
                            return percentage;
                        },
                        color: '#fff',
                        font: {
                            weight: 'bold',
                            size: 12
                        }
                    }
                }
            }
        });
        
        // Firewall Rules Chart
        const firewallData = {json.dumps(firewall_stats)};
        
        // Blocked Ports
        const portsCtx = document.getElementById('portsChart').getContext('2d');
        
        // Get top ports
        const portEntries = Object.entries(firewallData.ports);
        portEntries.sort((a, b) => b[1] - a[1]);
        const topPorts = portEntries.slice(0, 8);
        
        const portsChart = new Chart(portsCtx, {
            type: 'bar',
            data: {
                labels: topPorts.map(entry => entry[0]),
                datasets: [{
                    label: 'Blocked Attempts',
                    data: topPorts.map(entry => entry[1]),
                    backgroundColor: colors[0],
                    borderColor: colors[0].replace('0.8', '1.0'),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: {
                        display: true,
                        text: 'Top Blocked Ports'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Count'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Port'
                        }
                    }
                }
            }
        });
        
        // Blocked Protocols
        const protocolsCtx = document.getElementById('protocolsChart').getContext('2d');
        
        const protocolEntries = Object.entries(firewallData.protocols);
        
        const protocolsChart = new Chart(protocolsCtx, {
            type: 'pie',
            data: {
                labels: protocolEntries.map(entry => entry[0]),
                datasets: [{
                    data: protocolEntries.map(entry => entry[1]),
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'right',
                    },
                    title: {
                        display: true,
                        text: 'Blocked Protocols'
                    },
                        datalabels: {
                            formatter: (value, ctx) => {
                                let sum = 0;
                                let dataArr = ctx.chart.data.datasets[0].data;
                                dataArr.map(data => {
                                    sum += data;
                                });
                                let percentage = (value * 100 / sum).toFixed(1) + '%';
                                return percentage;
                            },
                            color: '#fff',
                            font: {
                                weight: 'bold',
                                size: 12
                            }
                        }
                    }
                }
            });
        """
    
    # Write the HTML content to a file
    print(f"Writing HTML report to {report_path}...")
    with open(report_path, 'w') as f:
        f.write(html_content)
    
    print(f"Report generated successfully at {report_path}")
    return report_path

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Security Dashboard Generator')
    parser.add_argument('--update-only', action='store_true', help='Update the report without opening browser')
    parser.add_argument('--refresh-interval', type=int, default=300, help='Auto-refresh interval in seconds (default: 300)')
    parser.add_argument('--no-refresh', action='store_true', help='Disable auto-refresh')
    args = parser.parse_args()
    
    # Generate report
    auto_refresh = not args.no_refresh
    report_path = generate_html_report(auto_refresh=auto_refresh, refresh_interval=args.refresh_interval)
    
    # Open report in web browser if not in update-only mode
    if not args.update_only:
        webbrowser.open(f"file://{report_path}")
    
    print(f"Dashboard updated successfully. Path: {report_path}")
    return report_path

if __name__ == "__main__":
    main()

