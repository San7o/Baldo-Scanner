#! /bin/sh
qemu-system-x86_64 \
    -kernel ../linux-kernel-module/linux/arch/x86_64/boot/bzImage \
    -m 3G \
    -drive file=qemu-image.img,index=0,media=disk,format=raw \
    -chardev qemu-vdagent,id=ch1,name=vdagent,clipboard=on \
    -append "root=/dev/sda rw console=ttyS0" \
    -k it \
    --enable-kvm
