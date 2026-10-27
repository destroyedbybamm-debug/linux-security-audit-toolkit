import os 
import platform
import shutil
results = {"REVIEW": 0, "INFO": 0, "ERROR": 0, "PASS": 0}

def report(status, message):
    if status in results:
        results[status] += 1
    print(f"[{status}] {message}")

print("=== Linux Security Audit ToolKit ===")
print(f"Operating System: {platform.system()}")
print(f"Linux Release: {platform.release()}")
print(f"Python Version: {platform.python_version()}")

print("\n=== Security Checks ===")

firewall = shutil.which("ufw")

if firewall is not None:
    report("INFO", "UFW firewall tool is installed.")
else:
    report("REVIEW", "UFW firewall tool was not found.")

updates = "/etc/apt/apt.conf.d/20auto-upgrades"

if os.path.exists(updates):
    with open(updates, "r") as file:
        settings = file.read()

    update_lists_enabled = 'APT::Periodic::Update-Package-Lists "1";' in settings
    unattended_enabled = 'APT::Periodic::Unattended-Upgrade "1";' in settings

    if update_lists_enabled and unattended_enabled:
        report("INFO", "Automatic updates are enabled in the configuration.")
    else:
        report("REVIEW", "Automatic update settings need review.")
else:
    report("REVIEW", "Automatic update configuration file was not found.")
print("\n=== Package Update Check ===")

apt = shutil.which("apt")

if apt is None:
    report("REVIEW", "APT package manager was not found.")
else:
    result = os.popen("apt list --upgradable 2>/dev/null").read()
    packages = [
        line for line in result.splitlines()
        if "/" in line and "upgradable" not in line.lower()
    ]

    if packages:
        report("REVIEW", f"{len(packages)} package(s) have updates available.")
        for package in packages[:10]:
            print(f"  - {package.split('/')[0]}")
        if len(packages) > 10:
            print("  - Additional packages omitted.")
    else:
        report("INFO", "No upgradable packages were reported.")

print("\n=== SSH Security Check ===")

sshd_config = "/etc/ssh/sshd_config"
sshd = shutil.which("sshd")

if sshd is None or not os.path.exists(sshd_config):
    report("INFO", "SSH server configuration was not found.")
else:
    try:
        result = os.popen(
            "sshd -T 2>/dev/null"
        ).read().lower()

        if not result:
            print("[REVIEW] Could not read effective SSH settings.")
        else:
            for setting in [
                "permitrootlogin",
                "passwordauthentication"
            ]:
                matches = [
                    line for line in result.splitlines()
                    if line.startswith(setting + " ")
                ]

                if matches:
                    value = matches[0].split()[-1]
                    print(f"[INFO] {setting}: {value}")
                else:
                    print(f"[REVIEW] {setting} could not be checked.")
    except Exception:
        print("[REVIEW] SSH configuration check failed.")
print("\n=== Sensitive File Permissions Check ===")

sensitive_files = {
    "/etc/passwd": 0o644,
    "/etc/shadow": 0o640,
}

for path, max_mode in sensitive_files.items():
    if not os.path.exists(path):
        report("INFO", f"{path} was not found.")
        continue

    try:
        actual_mode = os.stat(path).st_mode & 0o777

        if actual_mode & ~max_mode:
            report(
                "REVIEW",
                f"{path} has permissions "
                f"{actual_mode:04o}; review expected "
                f"maximum {max_mode:04o}."
            )
        else:
            report(
                "INFO",
                f"{path} permissions: {actual_mode:04o}."
            )

    except OSError:
        report("ERROR", f"Could not check permissions for {path}.")
print("\n=== Authentication Log Check ===")

auth_logs = [
    "/var/log/auth.log",
    "/var/log/secure",
]

available_logs = [path for path in auth_logs if os.path.isfile(path)]

if not available_logs:
    report("INFO", "No standard authentication log file was found.")
else:
    for path in available_logs:
        try:
            with open(path, "r", errors="replace") as file:
                failed_logins = sum(
                    1 for line in file
                    if "failed password" in line.lower()
                    or "authentication failure" in line.lower()
                )

            report("INFO", f"Log checked: {path}")
            report("INFO", f"Matching failed-login entries: {failed_logins}")

            if failed_logins > 0:
                report(
                    "REVIEW",
                    "Failed-login entries were found. "
                    "Investigate timestamps and source details."
                )
            else:
                report(
                    "INFO",
                    "No matching failed-login entries were found in this log."
                )

        except OSError:
            report("ERROR", f"Could not read authentication log: {path}")

print("\n=== Audit Summary ===")
for status, count in results.items():
    print(f"{status}: {count}")

print("\nAudit complete.")
