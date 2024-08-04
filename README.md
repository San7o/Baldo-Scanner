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

![image](https://github.com/user-attachments/assets/2982a357-3c3f-4e1b-9255-7c6e3db5e92d)


Currently, the only supported platform is Linux.

## Dependencies

- `C++17` compiler

- `cmake` to build the project

- `curlpp` and `libcurl` to fetch web APIs

- `unzip`

- `openssl3.3`

- `libnl` 3.8.0

On `NixOS`, run:
```bash
nix-shell
```

On Ubuntu/debian:
```bash
sudo apt install curl libboost1.81-dev libcurlpp-dev libyara-dev libnl-3-dev
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
