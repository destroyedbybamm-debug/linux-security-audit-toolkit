import os 
import platform
import shutil

print("=== Linux Security Audit ToolKit ===")
print(f"Operating System: {platform.system()}")
print(f"Linux Release: {platform.release()}")
print(f"Python Version: {platform.python_version()}")

print("\n=== Security Checks ===")

firewall = shutil.which("ufw")

if firewall is not None:
	print("[INFO] UFW firewall tool is installed.")
else:
	print("[REVIEW] UFW firewall tool was not found.")
updates = "/etc/apt/apt.conf.d/20auto-upgrades"

if os.path.exists(updates):
    with open(updates, "r") as file:
        settings = file.read()

    update_lists_enabled = 'APT::Periodic::Update-Package-Lists "1";' in settings
    unattended_enabled = 'APT::Periodic::Unattended-Upgrade "1";' in settings

    if update_lists_enabled and unattended_enabled:
        print("[INFO] Automatic updates are enabled in the configuration.")
    else:
        print("[REVIEW] Automatic update settings need review.")
else:
    print("[REVIEW] Automatic update configuration file was not found.")

print("\nAudit complete. Review the findings before taking action.")


