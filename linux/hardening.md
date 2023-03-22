### Linux Hardening  

`sudo` - temporary elevation of privileges. Set up by file `/etc/sudoers`  
`visudo` - secure editing  
`pkexec nano /etc/sudoers` - recovering  
Example:  
```
gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas  
root    ALL=(ALL:ALL) ALL
```

You can use the following format to create new sudoers authorizations and to modify existing authorizations:  
```
username hostname=path/to/command
```
- `username` is the name of the user or group, for example, user1 or %group1.
- `hostname` is the name of the host on which the rule applies.
- `path/to/command` is the complete absolute path to the command. You can also limit the user to only performing a command with specific options and arguments by adding those options after the command path. If you do not specify any options, the user can use the command with all options.  

You can replace any of these variables with ALL to apply the rule to all users, hosts, or commands.  
With overly permissive rules, such as  `ALL ALL=(ALL) ALL`, all users are able to run all commands as all users on all hosts. This can lead to security risks.  

 `/etc/passwd` - User account information.  
 Example `root:x:0:0:root:/root:/bin/bash`
  - login name  
  - optional encrypted password
  - numerical user ID
  - numerical group ID
  - user name or comment field
  - user home directory
  - optional user command interpreter 

 `/etc/shadow` - optional encrypted password file  
 Example `root:*:19150:0:99999:7:::`  
 - login name
 - encrypted password
 - date of last password change
 - minimum password age
 - maximum password age
 - password warning period
 - password inactivity period
 - account expiration date
 - reserved field

`/etc/group` - file  is a text file that defines the groups on the system.  
There is one entry per line, with the following format:  
`group_name:password:GID:user_list`  
Example `adm:x:4:syslog,test`  
The fields are as follows:  
- group_name
- password
- GID
- user_list

`/etc/login.defs` - file defines the site-specific configuration for the shadow password suite.

 `/etc/%name%-` - Backup file for /etc/%name%   

 ### User and group management
 Users:  
 `usermod --lock user`  
 `usermod -p password user`  
 `sudo passwd user`  
 `sudo userdel user`  

 Groups:  
 `groupadd gr1`  
 `groupmod -n gr1 gr2` - modify a group definition on the system  
 `sudo groupdel gr2`  
 `sudo chgrp gr1 test`
 `sudo chmod 575 test/`

 ### Resources limit
 `/etc/security/limits.conf` - configuration file for the pam_limits module
 - core - limits the core file size (KB)
 - data - max data size (KB)
 - fsize - maximum filesize (KB)
 - memlock - max locked-in-memory address space (KB)
 - nofile - max number of open file descriptors
 - rss - max resident set size (KB)
 - stack - max stack size (KB)
 - cpu - max CPU time (MIN)
 - nproc - max number of processes
 - as - address space limit (KB)
 - maxlogins - max number of logins for this user
 - maxsyslogins - max number of logins on the system
 - priority - the priority to run user process with
 - locks - max number of file locks the user can hold
 - sigpending - max number of pending signals
 - msgqueue - max memory used by POSIX message queues (bytes)
 - nice - max nice priority allowed to raise to values: [-20, 19]
 - rtprio - max realtime priority
 - chroot - change root to directory (Debian-specific)  

 ### Access attributes
Example:  
`r w x` &emsp; `r w -` &emsp; `r - x`  
`4 2 1` &emsp; `4 2 0` &emsp; `4 0 1`  
&emsp; `7` &emsp;&emsp;&ensp;&nbsp; `6` &emsp;&emsp;&emsp;&nbsp; `5`  

`Setuid (suid)` - This bit is present for files which have executable permissions. The setuid bit simply indicates that when running the executable, it will set its permissions to that of the user who created it (owner), instead of setting it to the user who launched it.  
`Setgid (sgid)` - The setgid affects both files as well as directories. When used on a file, it executes with the privileges of the group of the user who owns it instead of executing with those of the group of the user who executed it.When the bit is set for a directory, the set of files in that directory will have the same group as the group of the parent directory, and not that of the user who created those files. This is used for file sharing since they can be now modified by all the users who are part of the group of the parent directory.  
`Sticky` - When a directory has the sticky bit set, its files can be deleted or renamed only by the file owner, directory owner and the root user. The command below shows how the sticky bit can be set.  

`chmod (change mode)` - changing permissions  
`chmod +x <file> chmod -x <file>`  
`chmod g+r <file> chmod g-r <file>`  
`chmod o+w <file> chmod o-w <file>`  
`chmod 660 <file>`  
`chmod u+s <file>` – set SUID  
`chmod g+s <file>` – set SGID  
`chmod +t <file>` – set Sticky Bit  

`chown (change owner)` - change file owner and group  
`chown [OPTION]... [OWNER][:[GROUP]] FILE...`  

`chgrp (change group)` - change group ownership  
`chgrp [OPTION]... GROUP FILE...`  

`umask (user mask)` - get or set the file mode creation mask  
`umask [-S][mask]`  
`umask 0002` - u=rwx,g=rwx,o=rx

### PAM (Pluggable Authentication Modules)
`Linux-PAM` separates the tasks of authentication into four independent management groups:
- account management;
- authentication management;
- password management;
- session management.

`account` - provide account verification types of service: has the user's password expired? Is this user permitted access to the requested service?  
`authentication` - authenticate a user and set up user credentials.  
`password` - this group's responsibility is the task of updating authentication mechanisms.  
`session` - this group of tasks cover things that should be done prior to a service being given and after it is withdrawn.  

`/etc/pam.conf` - the configuration file  
`/etc/pam.d` - the Linux-PAM configuration directory. Generally, if this directory is present, the `/etc/pam.conf` file is ignored.  
`/lib/se curity/` – modules PAM  
`/etc/security/` – configuration files for PAM environments  
`/usr/share/doc/pam-*/` – documentation  

Example:  
`sudo nano /etc/pam.d/common-auth` - limiting login attempts  

![](/pic/pam.png)

### Directory encryption
eCryptfs - an enterprise-class cryptographic filesystem for linux  
Migration of the user's home directory:  
`sudo ecryptfs-migrate-home -u user1`  
Encryption of the swap partition:  
`sudo ecryptfs-setup-swap`  
Recovery information:  
`ecryptfs-unwrap-passphrase`  
Install: `sudo apt install ecryptfs-utils`   
Example:  
`mount -t ecryptfs [SRC DIR] [DST DIR] -o [OPTIONS]`  
`mount  -t  ecryptfs  -o key=passphrase:passphrase_passwd_file=/mnt/usb/file.txt /secret
/secret`  

### Encryption of the home directory
`sudo adduser --encrypt -home user2`  

### LUKS (Linux Unified Key Setup )
The default LUKS (Linux Unified Key Setup) format (version) used by the cryptsetup tool.  
Preparing the disk:   
`sudo apt install gparted`  
LUKS installation (should be installed by default):  
`sudo apt -get install cryptsetup`  

### LUKS partition encryption
Preparing the partition:  
`sudo cryptsetup -y -v --type luks2 luksFormat /dev/sdb1`  
Mounting a partition:  
`sudo cryptsetup luksOpen /dev/sdb1 disk`
`ls /dev/mapper/disk name`  
Formatting the partition:  
`sudo dd if=/dev/zero of=/dev/mapper/diskname`  
`sudo mkfs.ext4 /dev/mapper/diskname`  

### LUKS partition encryption
Mounting "open" section:  
`mkdir .secret`  
`sudo mount /dev/mapper/disk .secret/`  
Shutdown:  
`sudo umount .secret`  
`sudo cryptsetup luksClose disk`  


### Main log files

Debian:  
`sudo cat /var/log/auth.log`  
`sudo cat /var/log/syslog`  

Red Hat:  
`sudo cat /var/log/messages`  
`sudo cat /var/log/secure`  

`/var/log/kern.log` – kernel events (debian);  
`/var/log/wtmp` `/var/run/utmp` – list of user visits (binary!);  
`/var/log/btmp` – list of failed user logins (binary!);  
`/var/log/fail2ban` – log fail2ban;  
`/var/log/suricata/suricata.log` (fast .log) – log suricata;  
`journalctl` – journal systemd.  

Viewing long texts:  
`sudo less /var/log/syslog`  
Viewing the last lines:  
`sudo tail /var/log/syslog`  
Tracking the appearance of new lines:  
`sudo tail -f /var/log/syslog`  
Searching for a substring in a text file:  
`sudo grep 'fail' syslog`  
`sudo grep -i 'fail' syslog` (case insensitive)  
User login and upload:  
`last (/var/log/wtmp )`  
Failed login attempts:  
`sudo last -f /var/log/btmp`  
List of users and date of last login:  
`lastlog`  

### Lynis 
Lynis — auditing, system hardening, compliance testing  

Install:  
`sudo apt-get install lynis`  

Typical test suite  
`sudo lynis audit system`  
Complete set of tests  
`sudo lynis audit system -c`  
Remote Host Scan  
`audit system remote <host>`  
[linux-hardening](https://xakep.ru/2018/10/15/linux-hardening/)