#!/usr/bin/env python3
"""Exporta 'show full-configuration' del FortiGate para analizarlo con fortigate_cis_checker.sh.

Se usa Netmiko porque, con el post-login banner activo (CIS 2.1.2), un 'ssh admin@fw "comando"'
no puede aceptar el banner y devuelve una salida vacia. Netmiko lo acepta automaticamente.

Uso: python3 fw_exportar_config.py FW-despues.conf
"""
import getpass
import sys

from netmiko import ConnectHandler

destino = sys.argv[1] if len(sys.argv) > 1 else "FW-config.conf"
conn = ConnectHandler(device_type="fortinet", host="10.24.56.129", username="admin",
                      password=getpass.getpass("Contrasena del FW: "))
with open(destino, "w", encoding="utf-8") as f:
    f.write(conn.send_command("show full-configuration", read_timeout=300))
conn.disconnect()
print("[+] Configuracion guardada en", destino)
