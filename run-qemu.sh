#! /bin/sh

# "-kernel" specifies the kernel image
# "-m" sets the amount of memory
# "-drive" specifies the disk image
# "-chardev" specifies the character device
# "-append" adds kernel parameters
#     - root=/dev/sda: root partition
#     - rw: read-write
#     - nokaslr: disable kernel address space layout randomization
#     - console=ttyS0: use serial port 0 as console
# "-k" sets the keyboard layout
# "--enable-kvm" enables Kernel-based Virtual Machine
# -s: shorthand for -gdb tcp::1234, i.e. start gdbserver on TCP port 1234
# -S: freeze CPU at startup. Waits for gdb to connect.
#     You must type 'c' in the monitor to start execution
qemu-system-x86_64 \
    -kernel linux/arch/x86/boot/bzImage \
    -m 3G \
    -drive file=qemu-image.img,index=0,media=disk,format=raw \
    -chardev qemu-vdagent,id=ch1,name=vdagent,clipboard=on \
    -append "nokaslr root=/dev/sda debug rw console=ttyS0" \
    -k it \
    --enable-kvm \
    -s \
