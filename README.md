
🐧 Linux Commands  
Cheat Sheet
===============================

system · hardware · file · process · network · permissions

⚡ Made by: _[Christian Zigah](https://github.com/zigahchristian)_  

### 📁 File & Directory

ls -al               # list all (incl. hidden)
pwd                  # current path
mkdir dir            # create dir
rm -rf dir           # force remove
cp file1 file2       # copy
mv old new           # rename/move
ln -s /path link     # symlink
touch f              # create/update
head -n 5 file       # first 5 lines
tail -f log          # follow log

### ⚙️ System & Hardware

uname -a             # kernel all info
cat /proc/cpuinfo    # CPU details
free -h              # memory (human)
lscpu                # core/arch
lsblk                # block devices
dmesg | tail         # last boot messages
lspci -tv            # PCI tree
lsusb -tv            # USB tree
hdparm -tT /dev/sda  # read speed test
badblocks -s /dev/sda

### 🔍 Process & Performance

ps aux               # all processes
top / htop           # interactive
kill -9 PID          # force kill
pgrep firefox        # find PID
pstree               # tree view
lsof -i              # open connections
netstat -tlnp        # listening ports
vmstat 1             # swap/cpu
iostat -xnk 2        # disk io
strace -p PID        # syscalls

### 🌐 Networking & Transfer

ip a                 # show addresses
ping google.com      # ICMP test
dig domain.com ANY   # DNS lookup
curl -I https://x.com
wget url             # download file
scp file user@host:/path
rsync -av src/ dest/
ssh -L 8080:local:80 user@host
netstat -pnltu       # active ports

### 🔐 Permissions & Users

chmod 755 file       # rwxr-xr-x
chown user:group file
whoami               # current user
id                   # uid/gid info
useradd -m sam       # create user
passwd sam           # set password
usermod -aG sudo sam # add to sudo
groups               # my groups
last                 # last logins
w / who              # logged in

### 📦 Packages & Archives

yum install pkg      # RHEL/CentOS
rpm -ivh pkg.rpm     # local install
dnf install pkg      # newer fedora
tar -zcvf a.tgz dir/ # compress
tar -xvf a.tgz       # extract
gzip file ; gunzip file.gz
./configure && make && make install   # from source

🧑‍🤝‍🧑 User management – full reference
-----------------------------------------

**🔹 add a user**
useradd username                 # create user (defaults)
useradd -m -s /bin/bash alice    # -m create home, -s set shell
adduser bob                      # friendlier (some distros)

**🔹 set / change password**
passwd alice                     # set or change password
passwd -e alice                  # force password expire at next login

**🔹 modify existing user**
usermod -L bob                   # lock account (disable login)
usermod -U bob                   # unlock account
usermod -s /sbin/nologin bob     # change login shell (prevent login)
usermod -d /home/newhome -m bob  # move home directory
usermod -aG wheel bob            # add to supplementary group (wheel for sudo)
usermod -G docker bob            # change primary group (danger: remove from others)
usermod -c "Bobby Tables" bob    # add comment / full name

**🔹 delete user**
userdel bob                      # remove user (keeps home)
userdel -r bob                   # remove user + home + mail spool

**🔹 groups**
groupadd developers              # create group
groupdel developers              # delete group
groupmod -n newname oldname      # rename group
gpasswd -a alice developers      # add user to group
gpasswd -d alice developers      # remove user from group
groups alice                     # show groups of user

**🔹 privileges (sudo)**
visudo                           # edit /etc/sudoers safely
# give full sudo:   alice ALL=(ALL) ALL
# group sudo:       %developers ALL=(ALL) ALL
# passwordless:     alice ALL=(ALL) NOPASSWD: ALL

**🔹 user info & status**
id alice                         # uid, gid, groups
finger alice                     # login info (if installed)
chage -l alice                   # password expiry details
chage -E 2025-12-31 alice        # set account expiry date
chage -M 90 alice                # max days before password change

**🔹 switch user / become root**
su - alice                       # switch to alice (login shell)
sudo -i                          # become root with own env
sudo -u www-data command         # run command as other user

**🔹 system users (service accounts)**
useradd -r -s /usr/sbin/nologin appservice   # -r = system account
# system users have uid < 1000 (or SYS\_UID\_MIN) and no login

⏳ Boot & Runlevels
------------------

BIOS → MBR → GRUB → kernel → init → runlevel
runlevel 3 = full multiuser console, 5 = with GUI
who -r               # show current runlevel
init 1               # switch to single user
shutdown -h +10      # halt in 10 minutes
systemctl get-default
journalctl -b        # logs since boot

🖥️ Hardware Details
--------------------

lshw                 # full hardware info
dmidecode            # BIOS/DMI/SMBIOS
lsmod                # kernel modules
ethtool eth0         # NIC info
mount | column -t    # mounted fs
df -hT               # disk usage + fstype
du -sh /\* 2>/dev/null| sort -h   # folder sizes

🗄️ File System & Disk
----------------------

find /home -size +100M -exec ls -lh {} \\;
find . -mtime -7     # modified last 7 days
find . -name "\*.conf" -not -path "./.git/\*"
mkfs.ext4 /dev/sdb1  # format
mount /dev/sdb1 /mnt/data
blkid                # UUIDs
tune2fs -l /dev/sda1 | grep -i inode
fsck /dev/sdb1       # check consistency (unmounted)

📊 Performance & Monitoring
---------------------------

\# load average: 1.0 per core is full
ps aux --sort=-%mem | head -12    # top mem hogs
iotop                # io per process (root)
dstat                # all-in-one
mpstat -P ALL 2      # per-cpu usage
sar -n DEV 1 5       # network stats
ss -tunap            # modern socket stats
lsof | grep /var/log   # which process uses log

⌨️ Advanced Command Line
------------------------

\# xargs example: find . -name "\*.log" | xargs rm -f
awk '{print $NF}' file            # last field
sed -i '/^#/d' config             # remove comment lines
cut -d: -f1,6 /etc/passwd
!!                                  # run last command
!$                                  # last argument
cd -                                # previous dir
mkdir -p project/{src,bin,docs}    # brace expansion

🌍 Networking
-------------

ip -br -c a           # brief coloured IPs
ss -lntu              # listening ports
nc -zv 10.0.0.1 22    # check if port open
traceroute -T google.com 80   # tcp route
dig +short txt o-o.myaddr.l.google.com @ns1.google.com   # public IP
curl ifconfig.me
wget --mirror --convert-links http://site.com/   # mirror site

🔑 SSH & Remote Access
----------------------

ssh -J bastion host   # jump host
ssh-keygen -t ed25519 -C "note"
ssh-copy-id user@host
# ssh config ( ~/.ssh/config )
Host myserver
    HostName 192.168.1.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id\_rsa

🧱 Firewall (iptables/firewalld)
--------------------------------

iptables -L -n -v --line-numbers
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
firewall-cmd --list-all
firewall-cmd --add-service=http --permanent
firewall-cmd --reload

🐙 Git shortlog
---------------

git log --oneline --graph --all
git commit --amend -m "new message"
git rebase -i HEAD~3
git stash ; git pull --rebase ; git stash pop
git remote -v
git cherry-pick abc123

⚙️ systemd
----------

systemctl list-units --type=service --state=running
systemctl enable --now service
journalctl -u nginx -f -o cat
journalctl --since "1 hour ago"
systemd-analyze blame            # boot time

**Copyright 2026 Christian Zigah  
SAHAZA IT TRAINING**

**

📌 **student handout** – designed for quick lookup + deep reference.

**