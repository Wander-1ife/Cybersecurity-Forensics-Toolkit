import os
import psutil
import platform
import subprocess
from datetime import datetime, timedelta
import json
import socket

def get_system_info():
    """Collect basic system information."""
    os_info = platform.uname()
    memory_info = psutil.virtual_memory()
    swap_info = psutil.swap_memory()
    disk_partitions = psutil.disk_partitions()
    disk_usage = psutil.disk_usage('/')
    network_interfaces = psutil.net_if_addrs()
    battery_info = psutil.sensors_battery()

    system_info = {
        "OS": os_info.system,
        "OS Version": os_info.version,
        "OS Release": os_info.release,
        "Architecture": os_info.machine,
        "Hostname": os_info.node,
        "Processor": os_info.processor,  # Using platform.processor()
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
        "CPU Cores": psutil.cpu_count(logical=False),
        "Logical CPUs": psutil.cpu_count(logical=True),
        "CPU Frequency": psutil.cpu_freq().current if psutil.cpu_freq() else "N/A",  # Using psutil.cpu_freq() for CPU frequency
        "Memory Total": memory_info.total,
        "Memory Available": memory_info.available,
        "Memory Used": memory_info.used,
        "Swap Total": swap_info.total,
        "Swap Used": swap_info.used,
        "Disk Partitions": [{"Device": partition.device, "Mountpoint": partition.mountpoint, "Filesystem": partition.fstype} for partition in disk_partitions],
        "Disk Usage": {
            "Total": disk_usage.total,
            "Used": disk_usage.used,
            "Free": disk_usage.free,
            "Percent Used": disk_usage.percent
        },
        "Network Interfaces": format_network_interfaces(network_interfaces),  # Modified this line
        "Battery Status": battery_info.percent if battery_info else "N/A",
    }
    return system_info

def format_network_interfaces(network_interfaces):
    """Format network interface information for display."""
    formatted_interfaces = []
    for interface, addresses in network_interfaces.items():
        # Extract IPv4 address (ignoring IPv6 and other details)
        ipv4_address = None
        for addr in addresses:
            if addr.family == socket.AF_INET:
                ipv4_address = addr.address
                break
        
        if ipv4_address:
            formatted_interfaces.append(f"{interface}: {ipv4_address}")
        else:
            formatted_interfaces.append(f"{interface}: No IPv4 address")
    
    return formatted_interfaces

def get_users():
    """List all user accounts on the system."""
    try:
        output = subprocess.check_output("net user", shell=True, text=True)
        return {"Users": output.strip().split("\n")}
    except Exception as e:
        return {"Error": f"Failed to retrieve users: {e}"}

def is_system_process(proc):
    """Check if a process is a system process."""
    system_accounts = ['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE']
    try:
        if proc.info['username'] in system_accounts:
            return True
        if proc.info['exe'] and proc.info['exe'].lower().startswith(os.environ['WINDIR'].lower()):
            return True
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        return True
    return False

def get_running_processes():
    """Retrieve a list of running processes, excluding system background processes."""
    processes = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'exe']):
        try:
            if not is_system_process(proc):
                processes.append({
                    "PID": proc.info['pid'],
                    "Name": proc.info['name'],
                    "User": proc.info['username'],
                    "Executable": proc.info['exe']
                })
        except psutil.NoSuchProcess:
            continue
    return processes

def get_network_connections():
    """Retrieve a list of active network connections."""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            "Local Address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
            "Remote Address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
            "Status": conn.status
        })
    return connections

def get_recent_files(directory, days):
    """List recently accessed files in a directory, filtering by access time."""
    recent_files = []
    cutoff_time = datetime.now() - timedelta(days=days)
    
    # Use os.scandir for more efficient directory traversal
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                access_time = os.path.getatime(file_path)
                if datetime.fromtimestamp(access_time) > cutoff_time:  # Only include files accessed within the last 'days' days
                    recent_files.append({
                        "File": file_path,
                        "Last Accessed": datetime.fromtimestamp(access_time).strftime('%Y-%m-%d %H:%M:%S')
                    })
            except Exception:
                continue
    return recent_files

def format_forensics_output(forensics_data):
    """Format the collected forensics data into human-readable text."""
    output = []
    
    # System Information
    output.append("=== System Information ===")
    for key, value in forensics_data["System Information"].items():
        if isinstance(value, dict):
            output.append(f"{key}:")
            for subkey, subvalue in value.items():
                output.append(f"  {subkey}: {subvalue}")
        elif isinstance(value, list):
            output.append(f"{key}:")
            for item in value:
                output.append(f"  {item}")
        else:
            output.append(f"{key}: {value}")
    
    output.append("\n=== Users ===")
    if "Users" in forensics_data:
        for user in forensics_data["Users"]["Users"]:
            output.append(f"- {user}")
    else:
        output.append(f"Error: {forensics_data['Users']['Error']}")
    
    output.append("\n=== Running Processes ===")
    for process in forensics_data["Running Processes"]:
        output.append(f"PID: {process['PID']} | Name: {process['Name']} | User: {process['User']} | Executable: {process['Executable']}")
    
    output.append("\n=== Network Connections ===")
    for connection in forensics_data["Network Connections"]:
        output.append(f"Local Address: {connection['Local Address']} | Remote Address: {connection['Remote Address']} | Status: {connection['Status']}")
    
    output.append("\n=== Recent Files ===")
    for file in forensics_data["Recent Files"]:
        output.append(f"File: {file['File']} | Last Accessed: {file['Last Accessed']}")
    
    return "\n".join(output)

def main():
    print("Starting Windows Forensics...")
    forensics_data = {
        "System Information": get_system_info(),
        "Users": get_users(),
        "Running Processes": get_running_processes(),
        "Network Connections": get_network_connections(),
        "Recent Files": get_recent_files(directory=r"C:\Users\samia\OneDrive\Desktop", days=1)  # Adjust path and days as needed
    }

    # Format the forensics data into text
    formatted_output = format_forensics_output(forensics_data)

    # Save the formatted output to a .txt file
    script_directory = os.path.dirname(__file__)
    output_file = os.path.join(script_directory, "windows_forensics.txt")
    with open(output_file, "w") as f:
        f.write(formatted_output)

    print(f"Forensics data collected and saved to {output_file}")

if __name__ == "__main__":
    main()
