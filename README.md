  Linux Command Cheat Sheet · Student Handout \* { margin: 0; padding: 0; box-sizing: border-box; } body { background: #eef2f5; font-family: 'Segoe UI', 'Inter', system-ui, sans-serif; line-height: 1.5; color: #1e2b3c; padding: 2rem 1rem; } /\* main card \*/ .handout { max-width: 1300px; margin: 0 auto; background: white; border-radius: 2.5rem; box-shadow: 0 25px 50px -15px #1e293b80; overflow: hidden; padding: 2rem 2.5rem; } /\* header area – inspired by the visual slide title \*/ .header-grid { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; margin-bottom: 2rem; background: linear-gradient(105deg, #0b1c2f 0%, #1d3a5c 100%); padding: 1.5rem 2.2rem; border-radius: 2rem; color: white; } .title-section h1 { font-size: 2.8rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.2; background: linear-gradient(to right, #fff, #d3e5ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; } .title-section .sub { font-size: 1.2rem; color: #b6d0e8; margin-top: 0.5rem; display: block; } .slide-credit { background: rgba(255,255,255,0.1); padding: 0.8rem 1.5rem; border-radius: 60px; font-size: 0.9rem; border: 1px solid #41729f; backdrop-filter: blur(5px); } .slide-credit a { color: #ffd966; text-decoration: none; font-weight: 600; } .slide-credit i { font-style: normal; color: #a3c6ff; } /\* two‑col quick reference (mimics visual density of the slide) \*/ .quick-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin: 2.8rem 0 2rem 0; } .qcard { background: #f8fafd; border-radius: 1.8rem; padding: 1.5rem 1.2rem 1.2rem 1.5rem; border: 1px solid #dde7f0; box-shadow: 0 8px 15px -10px #abc0d0; } .qcard h3 { font-size: 1.3rem; font-weight: 600; color: #11324b; border-left: 6px solid #1e6f9f; padding-left: 0.8rem; margin-bottom: 1.2rem; background: linear-gradient(to right, #e6f0fa, transparent); } .qcard pre { background: #0f212f; color: #e3f2fd; padding: 1rem 1.2rem; border-radius: 20px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.8rem; line-height: 1.5; overflow-x: auto; white-space: pre-wrap; word-break: break-word; box-shadow: inset 0 0 0 1px #2a4055; } .qcard pre span.cmd { color: #f8d847; } /\* detailed sections (from original .md) \*/ .detail-section { margin-top: 3rem; } .detail-section h2 { font-size: 2rem; font-weight: 650; background: #e3edf6; padding: 0.5rem 1.5rem; border-radius: 50px; margin: 2.5rem 0 1.2rem 0; color: #0a2c3d; border-left: 8px solid #2c7eb6; scroll-margin-top: 20px; } .detail-section h3 { font-weight: 600; font-size: 1.5rem; margin: 2rem 0 0.8rem 0; color: #0f3b54; } /\* code blocks (dark) \*/ pre { background: #0b1b27; color: #e2eaf1; padding: 1.2rem 1.5rem; border-radius: 1.5rem; overflow-x: auto; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.9rem; line-height: 1.6; margin: 1.2rem 0; border: 1px solid #253e53; box-shadow: 0 8px 12px -8px #0b1b2750; } code:not(pre code) { background: #e1ecf5; color: #062c41; padding: 0.2rem 0.7rem; border-radius: 30px; font-size: 0.9rem; font-family: monospace; border: 1px solid #acccf0; } /\* table styling \*/ table { width: 100%; border-collapse: collapse; margin: 1.2rem 0; border-radius: 1.5rem; overflow: hidden; box-shadow: 0 6px 18px #d1dbe8; } th { background: #1b3a4e; color: white; font-weight: 600; padding: 0.8rem 1.2rem; } td { background: #f3f9ff; padding: 0.7rem 1.2rem; border-bottom: 1px solid #c2d6ec; } /\* license note \*/ .license { background: #ecf3fa; border-radius: 3rem; padding: 1.2rem 2rem; margin-top: 2rem; font-size: 0.85rem; color: #2f4858; border: 1px solid #bdd4ec; } /\* link style \*/ a { color: #256fa0; text-decoration: none; font-weight: 500; } a:hover { text-decoration: underline; } /\* additional visual \*/ hr { border: 2px dashed #acc6db; margin: 2rem 0; }

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