# firewall_manager.py

import subprocess
import threading
import time
import os
import ctypes


blocked_ips = {}
BLOCK_DURATION = 300  # Block for 300 seconds (5 minutes)

def block_ip(ip_address):
    """
    Adds a new inbound firewall rule to block a specific IP address
    for a temporary duration.
    
    The "decision" to block is made by ids_module.py.
    This function just executes the block.
    """
    
    
    if ip_address in blocked_ips:
        print(f"[FIREWALL] Renewing 5-min block for {ip_address}.")
        
        blocked_ips[ip_address].cancel()
    else:
        print(f"[FIREWALL] 🛡️ Blocking IP address: {ip_address} for 5 minutes.")

    rule_name = f"NIPS_Block_{ip_address}"
    
    try:
        
        subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True, text=True, check=False
        )
        
        
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip_address}"
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        
        
        unblock_timer = threading.Timer(BLOCK_DURATION, unblock_ip, [ip_address, rule_name])
        unblock_timer.start()
        
        
        blocked_ips[ip_address] = unblock_timer
        
    except subprocess.CalledProcessError as e:
        print(f"[FIREWALL ERROR] Failed to block {ip_address}. Are you running as Admin?")
        print(e.stderr)
    except FileNotFoundError:
        print("[FIREWALL ERROR] 'netsh' command not found. This script is for Windows.")

def unblock_ip(ip_address, rule_name):
    """
    Removes the firewall rule to unblock the IP address.
    Called by the threading.Timer.
    """
    print(f"[FIREWALL] ⏳ Unblocking IP address: {ip_address}")
    try:
        command = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
        
        if ip_address in blocked_ips:
            del blocked_ips[ip_address]
            
    except subprocess.CalledProcessError:
        pass 
    except FileNotFoundError:
        print("[FIREWALL ERROR] 'netsh' command not found.")

def check_admin_privileges():
    """Check if the script is running with administrator privileges."""
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = (ctypes.windll.shell32.IsUserAnAdmin() != 0)
    
    if not is_admin:
        print("="*60)
        print(" ERROR: This script requires Administrator privileges ")
        print("Please re-run this script as an Administrator.")
        print("="*60)
        time.sleep(5)
        exit()

def cleanup_all_blocks():
    """
    Called on shutdown. Cancels all pending timers
    and manually unblocks all IPs.
    """
    print("\n[FIREWALL] Shutdown detected. Cleaning up all active blocks...")
    
    
    items_to_clean = list(blocked_ips.items())
    
    if not items_to_clean:
        print("[FIREWALL] No active blocks to clean.")
        return

    for ip, timer in items_to_clean:
        
        timer.cancel()
        
        
        rule_name = f"NIPS_Block_{ip}"
        print(f"[FIREWALL]  Forcibly unblocking {ip}...")
        try:
            command = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            
            subprocess.run(command, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if ip in blocked_ips:
                del blocked_ips[ip]
        except Exception as e:
            print(f"[FIREWALL] Error during cleanup for {ip}: {e}")
    print("[FIREWALL] Cleanup complete.")
