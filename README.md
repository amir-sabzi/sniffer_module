# Packet sniffer LKM
this is a kernel module that sniffs packets come from a chosen interface and have specific destination port.  
it also implement a dedicated file system (sniffer_fs) to store a log of packets.you only can read the log and not permitted 
to modify or write in it.
## Prerequisites
I've used the Kernel <b>4.15.0-74-generic</b> to write this module and I know some functions and structures have changed 
in newer version of Linux Kernel specially 5.x. so I advice you to use proper Kernel version to install the module. to change Kernel version you can use tools like
ukuu.  
to install ukuu, follow these commands:  
```
$ sudo add-apt-repository ppa:teejee2008/ppa
$ sudo apt-get update
$ sudo apt-get install ukuu
```
and also make sure your device is connected to the Internet.
## Installing 
to install module you should Run GNU make in the source code directory.  
```
$ make
```
and then install the module:
```
$ insmod advanced_sniffer.ko
```
I've used loop device to make a file(e.g. image.img) accessible as a block device.to create a file for this purpose use following command:
```
dd if=/dev/zero of=./image.img bs=1024 count=100000
```
dd command allows you to create an iso file from a source file. we can use this file as a block device with loop 
file interface.  
after that to mount the file system you should dedicate a path as root point as follows:
```
mkdir temp
mount -o loop -t sniffer_fs ./image.img ./temp
```
## How to use
this module has 2 sys interface:  
* <b>sys_interface</b>: for setting the physical interface that we want to sniff packets on that.
* <b>sys_port</b>: for selecting a port number to monitor packets go to this port.
by default we sniff packets come through wifi interface (wlp2s0) and all destination ports. to change/show these configuration
use following commands:
```
$ cat <sys interface name> 
$ echo <physical interface/port number> > <sys interface name>
```
and also 5 proc interface:
* <b>protocol_stat</b>: show the statistics of protocols of packets come to the device.
* <b>srcAddr_stat</b>: list Top 10 IP addresses that send most packets to the device.
* <b>dstPort_stat</b>: list Top 10 Port addresses that receive most packets.
* <b>time_stat</b>: show time statitics of Kernel packet processing.
* <b>sniff_log</b>: show a log of sniffed packets in a human readable format.  

and I've implemented an IOCTL interface to push some commands like Reset proc files form user spcace, to use this 
interface you should compile <b>userspace.c</b> and execute corresponding object file.  
## Removing
to remove the module you should first umount the file system, for this purpose use following command:
```
$ umount ./temp
```
and then you can safely remove the module:
```
$ rmmod advanced_sniffer
```













