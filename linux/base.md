### Linux base

FHS (Filesystem Hierarchy Standard) - unified location of the main files and directories in UNIX systems  

`tree` - list contents of directories in a tree-like format
 Example: `tree -d -L 1`  

`mount` - mount a filesystem   
```
mount [-l|-h|-V]

mount -a [-fFnrsvw] [-t fstype] [-O optlist]

mount [-fnrsvw] [-o options] device|dir

mount [-fnrsvw] [-t fstype] [-o options] device dir
```

The standard form of the mount command is:  
`mount -t type device dir`  

`type fs`: ntfs, ext3, ext4  
`input output mode`: ro, rw  
`mounting point`: /mnt, /media

Example:  
```
mount /dev/sdb1 /media/sdb
mount -t vfat /dev/sdb1 /media/sdb
mount -t ntfs -o ro /dev/sdb1 /media/sdb
mount -o loop -t iso9660 disk.iso /media/disk
mount --bind /media/cdrom/data /home/user/data

umount /media/sdb
```  

`/etc/fstab` - The configuration file contains the necessary information to automate the process of mounting partitions.  

The syntax of a fstab entry is :  
[Device] [Mount Point] [File System Type] [Options] [Dump] [Pass]  
`sudo blkid` - To list your devices by UUID  
`sudo fdisk -l` - To list the drives and relevant partitions that are attached to your system  

`file` -  determine file type  
`magic` - file command's magic pattern file  
`/usr/share/misc/magic` - file specifies what patterns are to be tested for, what message or MIME type to print if a
particular pattern is found, and additional information to extract from the file  
`hexdump, hd` — ASCII, decimal, hexadecimal, octal dump  
`od` - dump files in octal and other formats  
`strings` - print the strings of printable characters in files.  
`objdump` - display information from object files.  
`xxd` - make a hexdump or do the reverse.

### Users

`/etc/passwd` -  file containing a list of system users  
`/etc/shadow` -  file containing a list of user passwords  
Example:  
```
useradd -D
sudo useradd xakep
sudo useradd xakep -s /bin/bash  
usermod --lock xakep  
usermod -p password xakep  
sudo passwd xakep  
sudo userdel xakep  
```

### User groups
`/etc/group`  -  file containing a list of user groups  
Example:  
```
groupadd ctf
groupmod -n ctf ftc
sudo groupdel ftc  
```

### Network
`/etc/hosts` - static table lookup for hostnames  
`hostname` - show or set the system's host name  
`domainname` - show or set the system's NIS/YP domain name  
`ypdomainname` - show or set the system's NIS/YP domain name  
`nisdomainname` - show or set the system's NIS/YP domain name  
`dnsdomainname` - show the system's DNS domain name  

`ifconfig` - configure a network interface
```
ifconfig [-v] [-a] [-s] [interface]
ifconfig [-v] interface [aftype] options | address ...
```  

`ip` - show / manipulate routing, network devices, interfaces and tunnels  
```
 ip addr
    Shows addresses assigned to all network interfaces.

ip neigh
    Shows the current neighbour table in kernel.

ip link set x up
     Bring up interface x.

ip link set x down
    Bring down interface x.

ip route
    Show table routes.
```

`/etc/network/interfaces` - network interface configuration for ifup and ifdown  
```
auto eth0
allow-hotplug eth1

iface eth0 inet dhcp

iface eth0 inet6 auto

iface eth1 inet static
    address 192.168.1.2/24
    gateway 192.168.1.1

iface eth1 inet6 static
    address fec0:0:0:1::2/64
    gateway fec0:0:0:1::1
```

### NetworkManager
```
sudo apt-get install network-manager
sudo apt-get install network-manager-gnome
```

### VPN support
Network Manager VPN support is based on a plug-in system.
```
network-manager-openvpn
network-manager-vpnc
network-manager-openconnect
```
Example:  
```
sudo start network-manager
sudo systemctl start NetworkManager.service
sudo systemctl enable NetworkManager.service
```

NetworkManager on the command line  
`nmcli help`  

### Managing interfaces
```
ifup \ ifdown
ifconfig eth0 up
nmcli d ...
```

### Viewing routes
```
netstat -r
netstat -nr
ip route

ip route add 192.168.4.0/24 via 192.168.1.1
route add -net 192.168.4.0/24 192.168.1.1
route add default gw 192.168.1.1 eth0

ip route delete 192.168.4.0/24 via 192.168.1.1
route del -net 192.168.4.0/24
```

### tcpdump
```
sudo tcpdump -i <interface>
sudo tcpdump -i <interface> -v или -vv
sudo tcpdump -i <interface> -w и -r
sudo tcpdump -i <interface> -A
sudo tcpdump -i <interface> <protocol>
```

### Security - AppArmor
To install the apparmor-profiles package from a terminal prompt:  
`sudo apt install apparmor-profiles`  
AppArmor profiles have two modes of execution:
- Complaining/Learning: profile violations are permitted and logged. Useful for testing and developing new profiles.
- Enforced/Confined: enforces profile policy as well as logging the violation.  

apparmor_status is used to view the current status of AppArmor profiles.  
`sudo apparmor_status`  

aa-complain places a profile into complain mode.  
`sudo aa-complain /path/to/bin`  
aa-enforce places a profile into enforce mode.  
`sudo aa-enforce /path/to/bin` 
apparmor_parser is used to load a profile into the kernel.  
`sudo apparmor_parser -r /etc/apparmor.d/profile.name`  
`sudo systemctl reload apparmor.service`  

[AppArmor documentation](https://ubuntu.com/server/docs/security-apparmor)