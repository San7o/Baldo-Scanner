#! /bin/sh

# Create an image with debian userspace

set -e

IMG=linux.img
MOUNT_DIR=/mnt/linux-image
SIZE=10g
FS=ext4
PACKAGES=sudo,vim,dhcpcd,libcurl4-openssl-dev,libyara-dev,libcurlpp-dev,libnl-genl-3-dev,tmux,libboost-program-options1.88.0-dev
IMG_USER=test
IMG_PASSWD=test

qemu-img create $IMG $SIZE
sudo mkfs.$FS $IMG

if [ ! -d $MOUNT_DIR ]; then
    sudo mkdir $MOUNT_DIR
fi

sudo mount -o loop $IMG $MOUNT_DIR

sudo debootstrap --include $PACKAGES --arch amd64 stable $MOUNT_DIR https://deb.debian.org/debian
sudo chroot $MOUNT_DIR /bin/bash -c "echo 'root:root' | chpasswd"
sudo chroot $MOUNT_DIR /bin/bash -c "chown root:root /etc/sudoers"
sudo chroot $MOUNT_DIR /bin/bash -c "useradd -m -u 1000 -s /bin/bash ${IMG_USER}"
sudo chroot $MOUNT_DIR /bin/bash -c "groupadd wheel"
sudo chroot $MOUNT_DIR /bin/bash -c "usermod -a -G wheel ${IMG_USER}"
sudo chroot $MOUNT_DIR /bin/bash -c "echo '${IMG_USER}:${IMG_PASSWD}' | chpasswd"

sudo umount -R $MOUNT_DIR
sudo rmdir $MOUNT_DIR
