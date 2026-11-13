#!/bin/bash
# Pruebas de demostracion (se ejecutan a mano, una por una, en el equipo indicado).
# Se dejan aqui como referencia de los comandos usados en el video.

# ---- Desde Windows (fuera de la red), PowerShell ----
# Test-NetConnection 192.168.128.160 -Port 443
# Test-NetConnection 192.168.128.160 -Port 22

# ---- Desde PC-Usuarios (VLAN 10) ----
nmap -p 22,23 10.24.56.65 10.24.56.66
ssh admin@10.24.56.65                                   # esperado: Connection refused
snmpwalk -v2c -c public 10.24.56.65 1.3.6.1.2.1.1       # esperado: Timeout
hydra -l admin -P clave.txt telnet://10.24.56.65         # esperado: can not connect
curl -4 -sI --max-time 10 http://example.com | head -1  # esperado: HTTP/1.1 200 OK
nc -4 -zv -w 5 portquiz.net 8080                        # esperado: timed out (bloqueado por el FW)

# ---- Desde PC-Kali (VLAN 99) ----
ssh -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1 \
    -o HostKeyAlgorithms=+ssh-rsa -c aes128-cbc -m hmac-sha1 admin@10.24.56.65   # show ip ssh / exit
snmpget -v2c -c ITLA-CIS-2356 10.24.56.65 1.3.6.1.2.1.1.5.0
tail -n 3000 /var/log/cisco.log | grep "GESTION-VTY denied" | tail -2
tail -n 3000 /var/log/cisco.log | grep "dstport=8080" | tail -1
