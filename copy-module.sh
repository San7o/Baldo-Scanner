#! /bin/sh

if [ ! -d /mnt/linux ]; then
    sudo mkdir /mnt/linux
fi

sudo mount qemu-image.img /mnt/linux
sudo cp -r kernel/ /mnt/linux/root/
sudo cp -r build/ /mnt/linux/root/
sudo cp shell.nix /mnt/linux/root/
sudo cp kernel-dev.nix /mnt/linux/root/
sudo umount /mnt/linux
