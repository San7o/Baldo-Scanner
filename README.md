# Baldo Scanner

Baldo Scanner is malware scanner for Linux systems. It can do static
malware analysis by signature matching and Yara rules. A database of
signatures and rules is automatically fetched from
[abuse.ch](https://abuse.ch/). Baldo scanner also implements a simple
firewall to block network traffic on provided ips, and a sandbox
environment to run untrusted applications.

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

### Structure

The application is composed of:

- A `kernel module`: This will hook into syscalls with `kprobes` based
on user defined rules, and send an event to the user space daemon via
`netlink` and/or `character devices`. A future implementation may use
`eBPF` for hooking.

- A `user space daemon`: An event driven daemon that listens for
  events from the kernel module, updates It's malware DB with online
  resources, spawns threads when analyzing with the analysis engine,
  sets iptables rules, runs processes in a sandbox environment. It
  logs the system calls into a DB.

- A `Malware DB`: Collection of malware signatures and `YARA` rules.

- An `analysis engine`: Scans a file's signature and binary data based
on `YARA` rules and signatures in the malware db.

- A `cli` application to interface with the daemon via `Berkley
  Sockets`

- There might be a web UI in the future


## Architecture Image

![image](https://github.com/user-attachments/assets/2982a357-3c3f-4e1b-9255-7c6e3db5e92d)


## Dependencies

- `C++17` compiler

- `cmake` to build the project

- `libcurl` and `libcurlpp` to fetch web APIs

- `unzip`

- `openssl3.3`

- `libnl` 3.8.0

- `libseccomp`

- `libyara`

- `boost::program_options`

Install dependencies on ubuntu/debian:

```bash
sudo apt install curl libboost1.81-dev libcurlpp-dev libyara-dev libnl-3-dev libseccomp-dev
```

## Building the project

To build the project with `cmake`, run:

```bash
cmake -Bbuild
cmake --build build
```

The binaries `build/baldo-daemon` and `build/baldo-cli` will be generated.

## Documentation

You can compile the docs with `doxygen`:

```bash
doxygen scripts/doxygen.conf
```

# Kernel virtual machine

To test the kernel module, we advise you to use a virtual machine. We
will now see how to build the kernel module and run a VM with qemu.

## Build the kernel Module

You need to build the scanner with `cmake` as specified above, and
compile the kernel module for your specific kernel version.

```bash
# Download and prepare the kernel
./scripts/download-linux.sh
cd linux-src
make defconfig
make modules_prepare
make vmlinux -j$(nproc)
make modules -j$(nproc)
make -j$(nproc)

# Build the kernel module
cd ..
make
```

## Run the image

```bash
./scripts/create-image.sh
./scripts/copy-module.sh
./scripts/run-qemu.sh
```

You can login with `root:root` or `test:test`.

# Talk with the kernel module

Both netlink and character devices are supported to communicate with
the kernel module by compiling the module with the flag `AV_NETLINK`
or `AV_CHAR_DEV`.

```bash
# Data Collection

echo "HELLO" > /dev/av_notify   # start collecting data
echo "FETCH" > /dev/av_notify   # copy the data (do this before reading)
cat /dev/av_notify              # read the data
echo "BYE"   > /dev/av_notify   # stop collecting data

# Firewall

echo "3646206603" > /dev/av_firewall  # block ip (in network byte notation)
```
