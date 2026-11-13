#!/bin/bash
# Configura Kali como servidor syslog (UDP 514) para R, SW y FW.
# Los logs de la red 10.24.56.0/24 se guardan en /var/log/cisco.log
set -e
apt install -y rsyslog
sed -i 's/^#module(load="imudp")/module(load="imudp")/; s/^#input(type="imudp" port="514")/input(type="imudp" port="514")/' /etc/rsyslog.conf
printf ':fromhost-ip, startswith, "10.24.56." /var/log/cisco.log\n& stop\n' > /etc/rsyslog.d/10-cisco.conf
systemctl restart rsyslog
ss -ulnp | grep 514
