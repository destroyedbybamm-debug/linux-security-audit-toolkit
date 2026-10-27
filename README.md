Linux Security Audit Toolkit

Overview

The Linux Security Audit Toolkit is a beginner cybersecurity project written in Python. It performs basic system checks and reports findings that may need further review.

Features

Identifies the operating system and Linux kernel release.

Displays the installed Python version.

Checks whether the UFW firewall utility is available.

Checks whether automatic update settings are enabled in the APT configuration file.

Reports findings directly in the terminal.

Technologies

Python

Linux

Ubuntu on Windows Subsystem for Linux (WSL2)

Git and GitHub

How to Run

Open an Ubuntu terminal.

Navigate to the project directory.

Run the following command:

python3 audit.py

Limitations

This is an educational auditing tool, not a complete security scanner. Finding the UFW utility does not confirm that the firewall is active. Checking APT configuration values does not confirm that updates are successfully running. WSL2 also has networking and security considerations that differ from a standalone Linux installation.

Learning Goals

This project demonstrates foundational Python scripting, operating-system information gathering, file handling, configuration checks, and basic security reporting.

Disclaimer

This tool is intended for educational use on systems you own or are authorized to assess. Review findings before making system changes.
