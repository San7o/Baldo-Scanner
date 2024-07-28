# linux-kernel-antivirus

## Project Statement

This project aims to build a MVP antivirus in C++ for a linux operating system, providing up to date network protection and static malware analysis.

The application is composed of:

- A `kernel module`: This will hook into syscalls with `kprobes` based on user defined rules, and send an event to the user space daemon via `netlink`. A future implementation
may use `eBPF` for hooking.

- A `user space daemon`: An event driven daemon that listens for events from the kernel module, updates It's malware DB with online resources, spawns threads when analyzing with the analysis engine, sets iptables rules.

- A `Malware DB`: Collection of malware signatures, malicious IPs and `YARA` rules.

- An `analysis engine`: Scans a file's signature and binary data based on `YARA` rules and
signatures in the malware db.

- A `cli` application to interface with the daemon via `Berkley Sockets`

- There might be a web application in the future

## Architecture Image

![image](https://github.com/user-attachments/assets/eb98d30b-05cf-4955-bc28-ce1c6c2ffe07)
