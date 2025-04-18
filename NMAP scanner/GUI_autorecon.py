import nmap
import json
import shodan
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

# SHODAN API Key (Replace with yours)
SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

# List of common Nmap scripts
NMAP_SCRIPTS = [
    "None", "vuln", "http-enum", "ftp-anon", "ssh-auth-methods", "ssl-cert", "smb-os-discovery"
]

# Decoy Options
DECOY_OPTIONS = ["No Decoy", "RND 5", "RND 10"]

def run_nmap_scan(target, decoy_mode, script=None):
    """ Run Nmap scan with optional decoy and script """
    scanner = nmap.PortScanner()
    
    # Set scan arguments based on user selection
    script_option = f"--script={script}" if script and script != "None" else ""
    
    if decoy_mode == "No Decoy":
        decoy_option = ""
    elif decoy_mode == "RND 5":
        decoy_option = "-D RND:5"
    elif decoy_mode == "RND 10":
        decoy_option = "-D RND:10"
    
    scan_command = f"-sS -sV -T4 --open {script_option} {decoy_option}"
    scanner.scan(target, arguments=scan_command)

    results = []
    for host in scanner.all_hosts():
        for port in scanner[host]['tcp']:
            service = scanner[host]['tcp'][port]
            results.append({
                "ip": host,
                "port": port,
                "state": service['state'],
                "service": service['name'],
                "version": service.get('version', 'unknown'),
                "script_output": service.get("script", {})
            })
    return results

def get_shodan_info(ip):
    """ Fetch additional details using Shodan API """
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        return api.host(ip)
    except:
        return {}

def save_results(results):
    """ Save scan results to JSON file """
    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

def start_scan():
    """ Start Nmap scan from GUI """
    target = target_entry.get()
    selected_script = script_dropdown.get()
    selected_decoy = decoy_dropdown.get()
    
    if not target:
        messagebox.showerror("Error", "Please enter a target IP or range!")
        return
    
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Scanning {target} with script: {selected_script} | Decoy Mode: {selected_decoy}...\n")

    scan_results = run_nmap_scan(target, selected_decoy, selected_script)

    for entry in scan_results:
        entry["shodan_info"] = get_shodan_info(entry["ip"])

    save_results(scan_results)

    for result in scan_results:
        output_text.insert(tk.END, f"\nIP: {result['ip']} | Port: {result['port']} | Service: {result['service']} ({result['version']})\n")
        if "script_output" in result:
            output_text.insert(tk.END, f"Script Output: {result['script_output']}\n")
    
    messagebox.showinfo("Scan Complete", "Results saved to results.json")

# GUI Setup
root = tk.Tk()
root.title("Network Scanner & Recon Tool")
root.geometry("600x500")

tk.Label(root, text="Enter Target IP/Range:").pack(pady=5)
target_entry = tk.Entry(root, width=50)
target_entry.pack(pady=5)

tk.Label(root, text="Select Nmap Script:").pack(pady=5)
script_dropdown = ttk.Combobox(root, values=NMAP_SCRIPTS, state="readonly")
script_dropdown.pack(pady=5)
script_dropdown.set("None")  # Default script

tk.Label(root, text="Select Decoy Mode:").pack(pady=5)
decoy_dropdown = ttk.Combobox(root, values=DECOY_OPTIONS, state="readonly")
decoy_dropdown.pack(pady=5)
decoy_dropdown.set("No Decoy")  # Default mode

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack(pady=10)

output_text = scrolledtext.ScrolledText(root, width=70, height=15)
output_text.pack(pady=5)

root.mainloop()
