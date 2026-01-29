#!/bin/sh

# This scripts downloads the linux kernel source in linux-src

set -e

KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.7.tar.xz
KERNEL_DEST=linux-src

if [ ! -d $KERNEL_DEST ]; then
    echo "Downloading linux"
    wget -O $KERNEL_DEST.tar.xz $KERNEL_URL
    tar -xf $KERNEL_DEST.tar.xz
    rm $KERNEL_DEST.tar.xz
    mv linux-* $KERNEL_DEST
    echo "Downloaded linux in $KERNEL_DEST"
else
    echo "Kernel sources already present"
fi
