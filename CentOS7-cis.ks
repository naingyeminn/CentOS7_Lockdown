#CIS - CentOS 7 Benchmark (v2.1.1) - Updated by Naing Ye Minn
#Copyright (c) 2015, Ross Hamilton. All rights reserved.
#Licenced under the BSD Licence See LICENCE file for details

install
lang en_US.UTF-8
keyboard --vckeymap=us --xlayouts='us'
timezone Asia/Rangoon --isUtc
auth --useshadow --passalgo=sha512 			# CIS 5.3.4
firewall --enabled
services --enabled=NetworkManager,sshd
eula --agreed
ignoredisk --only-use=sda
reboot

bootloader --location=mbr --append=" crashkernel=auto"
zerombr
clearpart --all --initlabel
part swap --asprimary --fstype="swap" --size=1024
part /boot --fstype xfs --size=200
part pv.01 --size=1 --grow
volgroup vg_root pv.01
logvol / --fstype xfs --name=root --vgname=vg_root --size=5120
# CIS 1.1.2-1.1.5
logvol /tmp --vgname vg_root --name tmp --size=500 --fsoptions="nodev,nosuid,noexec"
# CIS 1.1.6
logvol /var --vgname vg_root --name var --size=500
# CIS 1.1.11
logvol /var/log --vgname vg_root --name log --size=1024
# CIS 1.1.12
logvol /var/log/audit --vgname vg_root --name audit --size=1024
# CIS 1.1.13-1.1.14
logvol /home --vgname vg_root --name home --size=1024 --grow --fsoptions="nodev"

rootpw yourpasswordhere

cdrom

%packages --ignoremissing
@core
aide 				# CIS 1.3.1
tcp_wrappers			# CIS 3.4
rsyslog				# CIS 4.2.1
#cronie-anacron
-setroubleshoot 		# CIS 1.6.1.4
-mcstrans	 		# CIS 1.6.1.5
-telnet 			# CIS 2.3.4
-rsh-server 			# CIS 2.2.17
-rsh				# CIS 2.3.2
-ypbind				# CIS 2.1.1
-ypserv				# CIS 2.2.16
-tftp				# CIS 2.1.7
-tftp-server			# CIS 2.2.20
-talk				# CIS 2.3.3
-talk-server			# CIS 2.2.18
-xinetd				# CIS 2.1.7
-xorg-x11-server-common		# CIS 2.2.2
-avahi-daemon			# CIS 2.2.3
-cups				# CIS 2.2.4
-dhcp				# CIS 2.2.5
-openldap			# CIS 2.2.6
%end

%post --log=/root/postinstall.log

###############################################################################
# /etc/fstab
# CIS 1.1.6 + 1.1.15-1.1.17
cat << EOF >> /etc/fstab
/tmp      /var/tmp    none    bind    0 0
none	/dev/shm	tmpfs	nosuid,nodev,noexec	0 0
EOF

###############################################################################

# Disable mounting of unneeded filesystems CIS 1.1.1 and CIS 3.5
cat << EOF >> /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs chmod a+t

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release	# CIS 1.2.3

systemctl enable firewalld			# CIS 3.6
systemctl enable rsyslog			# CIS 4.2.1.1
systemctl enable auditd				# CIS 4.1.2
systemctl enable crond				# CIS 5.1.1

# Set bootloader password				# CIS 1.5.3
# qwe123#@!
cat << EOF2 >> /etc/grub.d/01_users
#!/bin/sh -e

cat << EOF
set superusers="bootuser"
password_pbkdf2 bootuser grub.pbkdf2.sha512.10000.44D91DCFB72B53F27C58A4EAEBF29A210CB57469FB5CAA8935585856232A6CE70A2B58CE8BBAF7A9618848836F1793EC575AD1BF5959472D3AA5ECB6A05C92D2.89E0A18B9AB9080642209EAC8FC69CB988062579B68C27A16281900FFC79CE60AE1155409F78DDCFC92C40FF87A7C2F5A80899515B5CF9D15044E34658CBBD6B
EOF
EOF2

sed -i s/'^GRUB_CMDLINE_LINUX="'/'GRUB_CMDLINE_LINUX="audit=1 '/ /etc/default/grub  # CIS 4.1.3
grub_cfg='/boot/grub2/grub.cfg'
grub2-mkconfig -o ${grub_cfg}

# Restrict Core Dumps					# CIS 1.5.1
echo \* hard core 0 >> /etc/security/limits.conf

cat << EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0					# CIS 1.5.1
kernel.randomize_va_space = 2				# CIS 1.5.3
net.ipv4.ip_forward = 0					# CIS 3.1.1
net.ipv4.conf.all.send_redirects = 0			# CIS 3.1.2
net.ipv4.conf.default.send_redirects = 0		# CIS 3.1.2
net.ipv4.conf.all.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.default.accept_source_route = 0		# CIS 3.2.1
net.ipv4.conf.all.accept_redirects = 0 			# CIS 3.2.2
net.ipv4.conf.default.accept_redirects = 0 		# CIS 3.2.2
net.ipv4.conf.all.secure_redirects = 0 			# CIS 23.2.3
net.ipv4.conf.default.secure_redirects = 0 		# CIS 3.2.3
net.ipv4.conf.all.log_martians = 1 			# CIS 3.2.4
net.ipv4.conf.default.log_martians = 1 			# CIS 3.2.4
net.ipv4.icmp_echo_ignore_broadcasts = 1		# CIS 3.2.5
net.ipv4.icmp_ignore_bogus_error_responses = 1		# CIS 3.2.6
net.ipv4.conf.all.rp_filter = 1				# CIS 3.2.7
net.ipv4.conf.default.rp_filter = 1			# CIS 3.2.7
net.ipv4.tcp_syncookies = 1				# CIS 3.2.8
net.ipv6.conf.all.accept_ra = 0				# CIS 3.3.1
net.ipv6.conf.default.accept_ra = 0 			# CIS 3.3.1
net.ipv6.conf.all.accept_redirect = 0			# CIS 3.3.2
net.ipv6.conf.default.accept_redirect = 0		# CIS 3.3.2
net.ipv6.conf.all.disable_ipv6 = 1			# CIS 3.3.3
EOF

echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
echo "options ipv6 disable=1" >> /etc/modprobe.d/ipv6.conf
echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.d/ipv6.conf

cd /usr/lib/systemd/system
rm default.target
ln -s multi-user.target default.target

echo "ALL: ALL" >> /etc/hosts.deny			# CIS 3.4.3
chown root:root /etc/hosts.deny				# CIS 3.4.5
chmod 644 /etc/hosts.deny				# CIS 3.4.5

chown root:root /etc/rsyslog.conf
chmod 600 /etc/rsyslog.conf
# CIS 4.2.1.2 - 4.2.1.3  Configure /etc/rsyslog.conf - This is environment specific
cat << EOF >> /etc/rsyslog.conf
auth,user.* /var/log/user
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
EOF

touch /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chmod og-rwx /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log
chown root:root /var/log/user /var/log/kern.log /var/log/daemon.log /var/log/syslog /var/log/unused.log

# CIS 4.2.1.4 - 4.2.1.5  Configure rsyslog to Send Log to a Remote Log Host - This is environment specific
auditd_conf='/etc/audit/auditd.conf'
# CIS 4.1.1.1 Configure Audit Log Storage Size
sed -i 's/^max_log_file .*$/max_log_file = 1024/' ${auditd_conf}
# CIS 4.1.1.2 Disable system on Audit Log Full - This is VERY environment specific (and likely controversial)
sed -i 's/^space_left_action.*$/space_left_action = email/' ${auditd_conf}
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' ${auditd_conf}
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' ${auditd_conf}
# CIS 4.1.1.3 Keep All Auditing Information
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' ${auditd_conf}

# CIS 5.1.2-5.1.7
chown root:root /etc/anacrontab	/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# CIS 5.1.8
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow



# CIS 4.1.4 - 4.1.18
cat << EOF >> /etc/audit/rules.d/audit.rules

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope

-w /var/log/sudo.log -p wa -k actions

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-a always,exit -F path=/usr/bin/wall -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/write -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/pkexec -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/netreport -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/usernetctl -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib/polkit-1/polkit-agent-helper-1 -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/utempter/utempter -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

-e 2
EOF

sed -i "1 i /var/log/boot.log" /etc/logrotate.d/syslog 			# CIS 4.3

sshd_config='/etc/ssh/sshd_config'
chown root:root ${sshd_config}						# CIS 5.2.1
chmod 600 ${sshd_config}						# CIS 5.2.1
sed -i "s/\#Protocol/Protocol/" ${sshd_config}				# CIS 5.2.2
sed -i "s/\#LogLevel/LogLevel/" ${sshd_config}				# CIS 5.2.3
sed -i "s/X11Forwarding yes/X11Forwarding no/" ${sshd_config}		# CIS 5.2.4
sed -i "s/\#MaxAuthTries 6/MaxAuthTries 4/" ${sshd_config}		# CIS 5.2.5
sed -i "s/\#IgnoreRhosts yes/IgnoreRhosts yes/" ${sshd_config}		# CIS 5.2.6
sed -i "s/\#HostbasedAuthentication no/HostbasedAuthentication no/" ${sshd_config}	# CIS 5.2.7
sed -i "s/\#PermitRootLogin yes/PermitRootLogin no/" ${sshd_config}	# CIS 5.2.8
sed -i "s/\#PermitEmptyPasswords no/PermitEmptyPasswords no/" ${sshd_config}	# CIS 5.2.9
sed -i "s/\#PermitUserEnvironment no/PermitUserEnvironment no/" ${sshd_config}	# CIS 5.2.10

line_num=$(grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
sed -i "${line_num} a MACs hmac-sha1-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-ripemd160" ${sshd_config}  # CIS 5.2.12
sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}  # CIS 5.2.11

sed -i "s/\#ClientAliveInterval 0/ClientAliveInterval 300/" ${sshd_config}	# CIS 5.2.13
sed -i "s/\#ClientAliveCountMax 3/ClientAliveCountMax 0/" ${sshd_config}	# CIS 5.2.13
sed -i "s/\#LoginGraceTime 2m/LoginGraceTime 60/" ${sshd_config}	# CIS 5.2.14
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" ${sshd_config}    	# CIS 5.2.16

# CIS 5.3.1
pwqual='/etc/security/pwquality.conf'
sed -i 's/^# minlen =.*$/minlen = 14/' ${pwqual}
sed -i 's/^# dcredit =.*$/dcredit = -1/' ${pwqual}
sed -i 's/^# ucredit =.*$/ucredit = -1/' ${pwqual}
sed -i 's/^# ocredit =.*$/ocredit = -1/' ${pwqual}
sed -i 's/^# lcredit =.*$/lcredit = -1/' ${pwqual}

# CIS 5.3.2
content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
echo -e "auth required pam_env.so
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > /etc/pam.d/password-auth

content="$(egrep -v "^#|^auth" /etc/pam.d/system-auth)"
echo -e "auth required pam_env.so
auth sufficient pam_unix.so remember=5
auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
auth required pam_deny.so\n$content" > /etc/pam.d/system-auth

# CIS 5.3.3
line_num="$(grep -n "^password[[:space:]]*sufficient[[:space:]]*pam_unix.so*" /etc/pam.d/system-auth | cut -d: -f1)"
sed -n "$line_num p" system-auth | grep remember || sed "${line_num} s/$/ remember=5/" /etc/pam.d/system-auth

login_defs=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}		# CIS 5.4.1.1
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}		# CIS 5.4.1.2
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}		# CIS 5.4.1.3

root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then
  usermod -g 0 root							# CIS 5.4.3
fi

# CIS 5.4.4
bashrc='/etc/bashrc'
#first umask cmd sets it for users, second umask cmd sets it for system reserved uids
#we want to alter the first one
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ ${bashrc}

bashprofile='/etc/profile'
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ ${bashprofile}

# CIS 5.5
cp /etc/securetty /etc/securetty.orig
#> /etc/securetty
cat << EOF > /etc/securetty
console
tty1
EOF

# CIS 5.6
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
usermod -G wheel root

[[ -w /etc/issue ]] && rm /etc/issue
[[ -w /etc/issue.net ]] && rm /etc/issue.net
touch /etc/issue /etc/issue.net
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

chown root:root ${grub_cfg}					# CIS 1.4.1
chmod 600 ${grub_cfg}
chmod 644 /etc/passwd						# CIS 6.1.2
chown root:root /etc/passwd
chmod 000 /etc/shadow						# CIS 6.1.3
chown root:root /etc/shadow
chmod 644 /etc/group						# CIS 6.1.4
chown root:root /etc/group
chmod 000 /etc/gshadow						# CIS 6.1.5
chown root:root /etc/gshadow

# Install AIDE     						# CIS 1.3.2
echo "0 5 * * * /usr/sbin/aide --check" >> /var/spool/cron/root
#Initialise last so it doesn't pick up changes made by the post-install of the KS
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'

%end
