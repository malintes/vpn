#!/bin/bash
# Orignal Script JohnFordTV's VPN Premium Script
# © Github.com/johndesu090
# Orignal Repository: https://github.com/malintes/vpn
# Modified Malintes
# Telegram: 
# Thanks for using this script, Enjoy Highspeed OpenVPN Service

#############################
#############################
# Variables (Can be changed depends on your preferred values)
# Script name
MyScriptName='All for one VPS'
MYIP=$(wget -qO- eth0.me);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# OpenSSH Ports
SSH_Port1='2205'

# Stunnel Ports
Stunnel_Port2='444' # through OpenSSH

# OpenVPN Ports
#OpenVPN_TCP_Port='1194'
#OpenVPN_UDP_Port='445'

# Privoxy Ports
Privoxy_Port1='9000'
Privoxy_Port2='9999'

# Squid Ports
Squid_Port1='3128'
Squid_Port2='8080'
Squid_Port3='8000'

# OpenVPN Config Download Port
OvpnDownload_Port='89' # Before changing this value, please read this document. It contains all unsafe ports for Google Chrome Browser, please read from line #23 to line #89: https://chromium.googlesource.com/chromium/src.git/+/refs/heads/raw/master/net/base/port_util.cc

# Server local time
MyVPS_Time='Europe/Luxembourg'
#############################