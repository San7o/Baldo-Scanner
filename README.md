# linux-kernel-antivirus

## What is this?

This project features a straightforward yet effective antivirus application written in C++ specifically designed for Linux operating systems. It incorporates static malware analysis capabilities, allowing it to scan files and executables for known malware signatures before they are executed or accessed, and to scan for YARA rules you can provide. A database of signatures and rules is autocatically fetched from [abuse.ch](https://abuse.ch/), ensuring your system is safeguarded against the latest threats. The antivirus comes with a simple firewall to block network traffic on provided ips and a sandbox environment to run untrusted applications.

## Cli usage

```bash
$> cli -h
Allowed options:

Generic options:
  -h [ --help ]            produce help message and exit
  -v [ --version ]         print version information and exit

Daemon options:
  -u [ --update ]          update Malware signatures database
  -q [ --quit ]            quit daemon gracefully
  -Q [ --force-quit ]      force quit daemon

Scan Options:
  -s [ --scan ] arg        scan a file or directory
  -t [ --type ] arg        type of scan: 0=signature 1=rules, 2=all[default]
  -l [ --load ] arg        load signatures CSV
  -y [ --yara-rules ] arg  set directory of yara rules
  --no-multithread         disable multithreading

Firewall options:
  -b [ --block-ip ] arg    block an IPv4 address
  -B [ --unblock-ip ] arg  unblock an IPv4 address

Sandbox Options:
  -S [ --sandbox ] arg     execute a file in a sandboxed environment, format:
                           name,arg1,arg2,...
```

### Talk with the kernel module

Both **netlink** and **character devices** are supported to communicate with the kernel module by compiling the module with the flag `AV_NETLINK` or `AV_CHAR_DEV`.

```bash
# Data Collection

echo "HELLO" > /dev/av_notify   # start collecting data
echo "FETCH" > /dev/av_notify   # copy the data (do this before reading)
cat /dev/av_notify              # read the data
echo "BYE"   > /dev/av_notify   # stop collecting data

# Firewall

echo "3646206603" > /dev/av_firewall  # block ip (in network byte notation)
```

### Structure

The application is composed of:

- A `kernel module`: This will hook into syscalls with `kprobes` based on user defined rules, and send an event to the user space daemon via `netlink` and/or `character devices`. A future implementation
may use `eBPF` for hooking.

- A `user space daemon`: An event driven daemon that listens for events from the kernel module, updates It's malware DB with online resources, spawns threads when analyzing with the analysis engine, sets iptables rules, runs processes in a sandbox environment. It logs the system calls into a DB.

- A `Malware DB`: Collection of malware signatures and `YARA` rules.

- An `analysis engine`: Scans a file's signature and binary data based on `YARA` rules and
signatures in the malware db.

- A `cli` application to interface with the daemon via `Berkley Sockets`

- There might be a web UI in the future


## Architecture Image

![image](https://github.com/user-attachments/assets/2982a357-3c3f-4e1b-9255-7c6e3db5e92d)


Currently, the only supported platform is Linux.

## Dependencies

- `C++17` compiler

- `cmake` to build the project

- `curlpp` and `libcurl` to fetch web APIs

- `unzip`

- `openssl3.3`

- `libnl` 3.8.0

- `libseccomp`

On `NixOS`, run:
```bash
nix-shell
```

On Ubuntu/debian:
```bash
sudo apt install curl libboost1.81-dev libcurlpp-dev libyara-dev libnl-3-dev libseccomp-dev
```

## Building the project

To build the project with `cmake`, run:

```bash
cmake -Bbuild
cmake --build build
```

The binaries `build/daemon` and `build/cli` will be generated.

## Documentation

You can compile the docs with `doxygen`:
```bash
doxygen doxygen.conf
```

# Kernel virtual machine

To test the kernel module, we advise you to use a virtual machine
so that your kernel won't break if bad stuff happens. This project
comes with a debian generated VM by running `create-image.sh`.

## Build the kernel Module

You need to build the antivirus with `cmake` as specified above, and
compile the kernel module for your specific kernel version. You
can clone the linux kernel and then run `make` in the root directory
of the project, this will compile the module. You can install all the
dependencies by entering the nix dev environment:
```bash
nix-shell kernel-dev.nix
make
```
## Run the image

You can copy the compiled binaries into the machine's `/root` with
`copy-module.sh`. Finally, you can run the machine with `run-qemu.sh`.
Here is a quick review of this:

```bash
./create-image.sh
./copy-module.sh
./run-qemu.sh
```

## Setup the image

If It's the first time you run the machine, you need to setup password
and/or network to login and/or have internet connection. You can do so
by mounting the image and running `chroot` on that folder. You need to
change your environment variables once inside to use the correct binaries.

Here is an example on how to do all of this:

```bash
sudo mount qemu-image.img /mnt/linux
sudo chroot /mnt/linux /bin/sh
root> export PATH="$PATH:/usr/sbin:/sbin:/bin"
root> passwd
root> apt install network-manager tmux
root> exit
sudo umount /mnt/linux
```

## Install dependencies with nix

You need some dependendencies to run the antivirus. All of them are defined
in `shell.nix`. I recommend giving the machine at least 10GB so that everything
will run smoothly. You can install the nix packet manager inside the VM
to install the required packets:

```bash
apt install xz-utils
curl -L https://nixos.org/nix/install > /tmp/install
chmod +x /tmp/install
/tmp/install --daemon
nix-channel --update
nix-shell   # enter the shell copied from the project
```

## Additional steps

You may want to change the keyboard layout. Use the following command:
```bash
apt install keyboard-configuration console-setup
```
it will automatically prompt to a menu where you can choose your keyboard settings.
