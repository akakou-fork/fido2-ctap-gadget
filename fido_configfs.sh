#!/bin/bash
set -x

configdir=/sys/kernel/config/usb_gadget
dev=fido2
report_desc=`pwd`/fido

if [ `whoami` != "root" ]; then
    echo "Must be root to run this script"
    exit 1;
fi

if [ ! -f $report_desc ]; then
    echo "ERROR: $report_desc must exist"
    exit 1;
fi

modprobe libcomposite
# expect systemd to have mounted configfs
if [ ! -d $configdir ]; then
    echo "systemd failed to mount $configdir"
    exit 1;
fi

cd $configdir
mkdir $dev
cd $dev
##
# create bogus vendor and product
##
echo 0xabcd > idVendor
echo 0xabcd > idProduct
##
# Add identity strings
##
mkdir strings/0x409
echo jejb > strings/0x409/manufacturer
echo "fido2 ctap" > strings/0x409/product
echo 12345678 > strings/0x409/serialnumber

##
# Now make the Config
##
mkdir configs/c.1
# conventional power number
echo 120 > configs/c.1/MaxPower
mkdir configs/c.1/strings/0x409
# should set configuration but HID would override

##
# now set up the function
##
mkdir functions/hid.usb0
# we're a non boot hid
echo 0 > functions/hid.usb0/protocol
echo 0 > functions/hid.usb0/subclass
##
# All CTAP protocols require 64 byte reports
##
echo 64 > functions/hid.usb0/report_length
##
# Set the compiled report descriptor
##
$report_desc  functions/hid.usb0/report_desc || exit 1

##
# now link the config to the interface
##
ln -s functions/hid.usb0 configs/c.1/
# modprobe dummy_hcd
# echo "dummy_udc.0" > UDC

ls /sys/class/udc > UDC


