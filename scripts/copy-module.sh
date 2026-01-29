#! /bin/sh

set -e

IMAGE=linux.img
MOUNT_DIR=/mnt/linux-image

if [ ! -d $MOUNT_DIR ]; then
    sudo mkdir $MOUNT_DIR
fi

sudo mount -o loop $IMAGE $MOUNT_DIR

sudo cp -r kernel/ $MOUNT_DIR/root/
sudo cp -r build/ $MOUNT_DIR/root/
sudo cp -r tests/ $MOUNT_DIR/root/

sudo umount -R $MOUNT_DIR
sudo rmdir $MOUNT_DIR

echo "Copied targets in image"
