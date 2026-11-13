#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cis_hardening.py - Auditoria y hardening basado en CIS Benchmarks
  - Router y switch: CIS Cisco IOS 15 Benchmark v4.1.1
  - Firewall:        CIS FortiGate 7.0.x Benchmark v1.3.0
Practica de Seguridad de Redes - ITLA
Autor: Angel Alcantara (2024-2356)

Modos de uso:
  python3 cis_hardening.py --auditar        Solo revisa los equipos y genera un informe (no cambia nada).
  python3 cis_hardening.py --aplicar        Revisa, aplica las reglas que fallan, guarda la config
                                            y genera un informe posterior.
Opciones:
  --equipo R|SW|FW Trabajar solo con un equipo.
  --usuario admin  Usuario SSH (por defecto: admin).
  --si             No pedir confirmacion antes de aplicar.
"""

import argparse
import getpass
import html
import os
import re
import sys
import time
from datetime import datetime

try:
    from netmiko import ConnectHandler
except ImportError:
    print("[!] Falta netmiko. Activa el venv o instala con: pip install netmiko")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Parametros del laboratorio (direccionamiento basado en la matricula 2024-2356)
# ---------------------------------------------------------------------------
RED_GESTION = "10.24.56.64"
WILDCARD_GESTION = "0.0.0.15"
KALI = "10.24.56.70"                      # estacion de administracion / syslog / SNMP
COMUNIDAD_SNMP = "ITLA-CIS-2356"
LISTA_AAA = "CIS-LOCAL"
BANNER = "Acceso solo para personal autorizado. Toda actividad es monitoreada."

MASCARA_GESTION = "255.255.255.240"
SERVICIOS_SALIDA = "HTTP HTTPS DNS ALL_ICMP NTP"   # servicios permitidos de la LAN hacia internet

EQUIPOS = [
    {
        "nombre": "R", "ip": "10.24.56.65", "tipo": "router", "device_type": "cisco_ios",
        "if_gestion": "Ethernet0/1.99",
        "if_proxy_arp": ["Ethernet0/0", "Ethernet0/1.10", "Ethernet0/1.99"],
        "if_urpf": ["Ethernet0/1.10", "Ethernet0/1.99"],
    },
    {
        "nombre": "SW", "ip": "10.24.56.66", "tipo": "switch", "device_type": "cisco_ios",
        "if_gestion": "Vlan99",
        "if_proxy_arp": ["Vlan99"],
        "if_urpf": [],
    },
    {
        "nombre": "FW", "ip": "10.24.56.129", "tipo": "firewall", "device_type": "fortinet",
        "if_wan": "port1", "if_lan": "port2", "ip_lan": "10.24.56.129",
    },
]

BASE = os.path.dirname(os.path.abspath(__file__))
DIR_REPORTES = os.path.join(BASE, "reportes")
DIR_CONFIGS = os.path.join(BASE, "running-configs")

CUMPLE, NO_CUMPLE, EXCEPCION, NA = "CUMPLE", "NO CUMPLE", "EXCEPCION", "N/A"


# ---------------------------------------------------------------------------
# Utilidades para leer la configuracion
# ---------------------------------------------------------------------------
def tiene(texto, patron):
    return re.search(patron, texto, re.M) is not None


def primera(texto, patron, defecto="No configurado"):
    m = re.search(patron, texto, re.M)
    return m.group(0).strip() if m else defecto


def bloques(run, encabezado):
    """Devuelve los bloques (encabezado + lineas con sangria) cuyo encabezado coincide."""
    resultado, actual = [], None
    for linea in run.splitlines():
        if re.match(encabezado, linea):
            actual = [linea]
            resultado.append(actual)
        elif actual is not None and linea.startswith(" "):
            actual.append(linea)
        else:
            actual = None
    return ["\n".join(b) for b in resultado]


def encabezados_vty(run):
    enc = re.findall(r"^line vty \d+(?: \d+)?$", run, re.M)
    return enc or ["line vty 0 4"]


def bloque_interfaz(run, interfaz):
    b = bloques(run, r"^interface " + re.escape(interfaz) + r"$")
    return b[0] if b else ""


def bits_rsa(salida):
    """Estima el tamano de la llave RSA principal a partir de 'show crypto key mypubkey rsa'."""
    for parte in salida.split("% Key pair was generated at:"):
        nombre = re.search(r"Key name:\s*(\S+)", parte)
        if not nombre or nombre.group(1).endswith(".server") or "Key Data:" not in parte:
            continue
        datos = parte.split("Key Data:", 1)[1]
        hexa = "".join(re.findall(r"\b[0-9A-Fa-f]{2,8}\b", datos))
        total = len(hexa) // 2          # bytes de la llave publica en DER
        if total < 200:
            return 1024
        if total < 400:
            return 2048
        return 4096
    return 0


def timeout_ok(bloque, maximo=10):
    m = re.search(r"exec-timeout (\d+)(?: (\d+))?", bloque)
    if not m:
        return False
    minutos, segundos = int(m.group(1)), int(m.group(2) or 0)
    return (minutos, segundos) != (0, 0) and (minutos * 60 + segundos) <= maximo * 60


# ---------------------------------------------------------------------------
# Reglas CIS elegidas
#   verificar(d, eq) -> (resultado, evidencia)   resultado: True / False / None (N/A)
#   corregir(d, eq, cred) -> lista de comandos (str o dict con confirmacion)
# ---------------------------------------------------------------------------
def r_aaa_new_model(d, eq):
    return tiene(d["run"], r"^aaa new-model"), primera(d["run"], r"^(no )?aaa new-model.*")


def r_aaa_login(d, eq):
    return tiene(d["run"], r"^aaa authentication login "), primera(d["run"], r"^aaa authentication login .*")


def r_aaa_enable(d, eq):
    return tiene(d["run"], r"^aaa authentication enable default"), primera(d["run"], r"^aaa authentication enable .*")


def r_con_auth(d, eq):
    b = bloques(d["run"], r"^line con 0")
    ok = bool(b) and "login authentication" in b[0]
    return ok, primera(b[0] if b else "", r"login authentication.*", "line con 0 sin 'login authentication'")


def r_vty_auth(d, eq):
    b = bloques(d["run"], r"^line vty ")
    ok = bool(b) and all("login authentication" in x for x in b)
    return ok, "Todas las VTY con lista AAA" if ok else "VTY sin 'login authentication'"


def r_privilegio(d, eq):
    altos = re.findall(r"^username (\S+) privilege (\d+)", d["run"], re.M)
    malos = [u for u, p in altos if int(p) > 1]
    return not malos, "Usuarios con privilegio >1: " + ", ".join(malos) if malos else "Todos los usuarios con privilege 1"


def r_vty_ssh(d, eq):
    b = bloques(d["run"], r"^line vty ")
    ok = bool(b) and all(re.search(r"transport input ssh\s*$", x, re.M) for x in b)
    ev = [primera(x, r"transport input.*", "transport input (por defecto)") for x in b]
    return ok, "; ".join(ev)


def r_aux_exec(d, eq):
    b = bloques(d["run"], r"^line aux 0")
    if not b:
        return None, "No hay linea AUX"
    return "no exec" in b[0], primera(b[0], r"no exec", "exec habilitado en AUX")


def r_acl_vty(d, eq):
    return tiene(d["run"], r"^ip access-list standard GESTION-VTY"), primera(d["run"], r"^ip access-list standard GESTION-VTY")


def r_access_class(d, eq):
    b = bloques(d["run"], r"^line vty ")
    ok = bool(b) and all("access-class GESTION-VTY in" in x for x in b)
    return ok, "access-class GESTION-VTY in" if ok else "VTY sin access-class"


def r_timeout_con(d, eq):
    b = bloques(d["run"], r"^line con 0")
    ok = bool(b) and timeout_ok(b[0])
    return ok, primera(b[0] if b else "", r"exec-timeout.*", "exec-timeout por defecto (no explicito)")


def r_timeout_vty(d, eq):
    b = bloques(d["run"], r"^line vty ")
    ok = bool(b) and all(timeout_ok(x) for x in b)
    return ok, primera(b[0] if b else "", r"exec-timeout.*", "exec-timeout por defecto (no explicito)")


def r_banner(tipo):
    def f(d, eq):
        return tiene(d["run"], r"^banner " + tipo), "banner " + tipo + (" configurado" if tiene(d["run"], r"^banner " + tipo) else " no configurado")
    return f


def r_enable_secret(d, eq):
    ok = tiene(d["run"], r"^enable secret") and not tiene(d["run"], r"^enable password")
    ev = "enable secret" if tiene(d["run"], r"^enable secret") else "solo 'enable password'"
    return ok, ev


def r_pass_enc(d, eq):
    return tiene(d["run"], r"^service password-encryption"), primera(d["run"], r"^(no )?service password-encryption")


def r_user_secret(d, eq):
    usuarios = re.findall(r"^username (\S+) .*", d["run"], re.M)
    sin_secret = re.findall(r"^username (\S+)(?!.* secret ).*$", d["run"], re.M)
    return bool(usuarios) and not sin_secret, "Sin secret: " + ", ".join(sin_secret) if sin_secret else "Todos con secret"


def r_snmp_public(d, eq):
    return not tiene(d["run"], r"^snmp-server community public\b"), primera(d["run"], r"^snmp-server community public.*", "Sin comunidad public")


def r_snmp_acl(d, eq):
    com = re.findall(r"^snmp-server community (\S+)(.*)$", d["run"], re.M)
    if not com:
        return None, "Sin comunidades SNMP"
    sin_acl = [c for c, resto in com if len(resto.split()) < 2]
    return not sin_acl, "Sin ACL: " + ", ".join(sin_acl) if sin_acl else "Todas las comunidades con ACL"


def r_snmp_acl_existe(d, eq):
    return tiene(d["run"], r"^ip access-list standard SNMP-GESTION"), primera(d["run"], r"^ip access-list standard SNMP-GESTION")


def r_snmp_host(d, eq):
    return tiene(d["run"], r"^snmp-server host "), primera(d["run"], r"^snmp-server host \S+")


def r_snmp_traps(d, eq):
    return tiene(d["run"], r"^snmp-server enable traps snmp"), primera(d["run"], r"^snmp-server enable traps snmp.*")


def r_rsa(d, eq):
    bits = bits_rsa(d["rsa"])
    return bits >= 2048, "Llave RSA de %s bits" % (bits or "?")


def r_ssh_timeout(d, eq):
    m = re.search(r"^ip ssh time-out (\d+)", d["run"], re.M)
    return bool(m) and int(m.group(1)) <= 60, m.group(0) if m else "Timeout por defecto (120 s)"


def r_ssh_retries(d, eq):
    m = re.search(r"[Aa]uthentication retries:\s*(\d+)", d["ssh"])
    return bool(m) and int(m.group(1)) <= 3, m.group(0) if m else "No se pudo leer"


def r_ssh_v2(d, eq):
    m = re.search(r"version (\d\.\d+)", d["ssh"])
    return bool(m) and m.group(1) == "2.0", "SSH version " + (m.group(1) if m else "?")


def r_cdp(d, eq):
    return "not enabled" in d["cdp"], "CDP deshabilitado" if "not enabled" in d["cdp"] else "CDP habilitado"


def r_bootp(d, eq):
    return tiene(d["run"], r"^no ip bootp server"), primera(d["run"], r"^no ip bootp server", "ip bootp server (por defecto)")


def r_dhcp(d, eq):
    return tiene(d["run"], r"^no service dhcp"), primera(d["run"], r"^no service dhcp", "service dhcp (por defecto)")


def r_simple(linea_cfg):
    def f(d, eq):
        return tiene(d["run"], "^" + re.escape(linea_cfg)), primera(d["run"], "^" + re.escape(linea_cfg), "No configurado")
    return f


def r_log_buffer(d, eq):
    return tiene(d["run"], r"^logging buffered \d+"), primera(d["run"], r"^logging buffered.*")


def r_log_host(d, eq):
    return tiene(d["run"], r"^logging (host )?\d+\.\d+\.\d+\.\d+"), primera(d["run"], r"^logging (host )?\d+\.\d+\.\d+\.\d+.*")


def r_log_trap(d, eq):
    return "level informational" in d["logging"], primera(d["logging"], r"Trap logging:.*", "No se pudo leer")


def r_log_source(d, eq):
    return tiene(d["run"], r"^logging source-interface "), primera(d["run"], r"^logging source-interface .*")


def r_proxy_arp(d, eq):
    malas = [i for i in eq["if_proxy_arp"] if "no ip proxy-arp" not in bloque_interfaz(d["run"], i)]
    return not malas, "Proxy ARP activo en: " + ", ".join(malas) if malas else "Proxy ARP deshabilitado"


def r_urpf(d, eq):
    if not eq["if_urpf"]:
        return None, "No aplica (equipo de capa 2)"
    malas = [i for i in eq["if_urpf"] if "ip verify unicast source reachable-via" not in bloque_interfaz(d["run"], i)]
    return not malas, "Sin uRPF en: " + ", ".join(malas) if malas else "uRPF en interfaces internas"


# --- Correcciones -----------------------------------------------------------
def c_aaa(d, eq, cred):
    return ["aaa new-model",
            "aaa authentication login default local",
            "aaa authentication login %s local" % LISTA_AAA,
            "aaa authentication enable default enable"]


def c_con_auth(d, eq, cred):
    return c_aaa(d, eq, cred) + ["line con 0", " login authentication %s" % LISTA_AAA, " exit"]


def c_vty(linea):
    def f(d, eq, cred):
        cmds = []
        for enc in encabezados_vty(d["run"]):
            cmds += [enc, " " + linea, " exit"]
        return cmds
    return f


def c_vty_auth(d, eq, cred):
    return c_aaa(d, eq, cred) + c_vty("login authentication %s" % LISTA_AAA)(d, eq, cred)


def c_usuario(d, eq, cred):
    u = cred["usuario"]
    return [{"cmd": "no username %s" % u, "confirmar": ""},
            "username %s privilege 1 secret %s" % (u, cred["nueva_clave"])]


def c_acl_vty(d, eq, cred):
    return ["ip access-list standard GESTION-VTY",
            " permit %s %s" % (RED_GESTION, WILDCARD_GESTION),
            " deny any log",
            " exit"]


def c_access_class(d, eq, cred):
    return c_acl_vty(d, eq, cred) + c_vty("access-class GESTION-VTY in")(d, eq, cred)


def c_enable_secret(d, eq, cred):
    return ["enable secret %s" % cred["nuevo_enable"], "no enable password"]


def c_acl_snmp(d, eq, cred):
    return ["ip access-list standard SNMP-GESTION", " permit %s" % KALI, " deny any log", " exit"]


def c_snmp_acl(d, eq, cred):
    cmds = c_acl_snmp(d, eq, cred)
    for c, resto in re.findall(r"^snmp-server community (\S+)(.*)$", d["run"], re.M):
        if len(resto.split()) < 2:
            cmds.append("no snmp-server community %s" % c)
    return cmds + ["snmp-server community %s RO SNMP-GESTION" % COMUNIDAD_SNMP]


def c_rsa(d, eq, cred):
    return [{"cmd": "crypto key generate rsa general-keys modulus 2048", "confirmar": "yes", "espera": 8}]


def c_interfaces(campo, linea):
    def f(d, eq, cred):
        cmds = []
        for i in eq[campo]:
            cmds += ["interface %s" % i, " " + linea, " exit"]
        return cmds
    return f


def fijo(*cmds):
    return lambda d, eq, cred: list(cmds)


# (id, titulo, nivel, verificar, corregir, excepciones {tipo: motivo}, grupo)
REGLAS = [
    ("1.1.1", "Enable 'aaa new-model'", 1, r_aaa_new_model, c_aaa, {}, "aaa"),
    ("1.1.2", "Enable 'aaa authentication login'", 1, r_aaa_login, c_aaa, {}, "aaa"),
    ("1.1.3", "Enable 'aaa authentication enable default'", 1, r_aaa_enable, c_aaa, {}, "aaa"),
    ("1.1.4", "Set 'login authentication' for 'line con 0'", 1, r_con_auth, c_con_auth, {}, None),
    ("1.1.6", "Set 'login authentication' for 'line vty'", 1, r_vty_auth, c_vty_auth, {}, None),
    ("1.2.1", "Set 'privilege 1' for local users", 1, r_privilegio, c_usuario, {}, "usuarios"),
    ("1.2.2", "Set 'transport input ssh' for 'line vty'", 1, r_vty_ssh, c_vty("transport input ssh"), {}, None),
    ("1.2.3", "Set 'no exec' for 'line aux 0'", 1, r_aux_exec, fijo("line aux 0", " no exec", " exit"), {}, None),
    ("1.2.4", "Create 'access-list' for use with 'line vty'", 1, r_acl_vty, c_acl_vty, {}, None),
    ("1.2.5", "Set 'access-class' for 'line vty'", 1, r_access_class, c_access_class, {}, None),
    ("1.2.7", "Set 'exec-timeout' <= 10 min for 'line con 0'", 1, r_timeout_con, fijo("line con 0", " exec-timeout 5 0", " exit"), {}, None),
    ("1.2.9", "Set 'exec-timeout' <= 10 min for 'line vty'", 1, r_timeout_vty, c_vty("exec-timeout 5 0"), {}, None),
    ("1.3.1", "Set the 'banner-text' for 'banner exec'", 1, r_banner("exec"), fijo("banner exec #%s#" % BANNER), {}, None),
    ("1.3.2", "Set the 'banner-text' for 'banner login'", 1, r_banner("login"), fijo("banner login #%s#" % BANNER), {}, None),
    ("1.3.3", "Set the 'banner-text' for 'banner motd'", 1, r_banner("motd"), fijo("banner motd #%s#" % BANNER), {}, None),
    ("1.4.1", "Set 'password' for 'enable secret'", 1, r_enable_secret, c_enable_secret, {}, None),
    ("1.4.2", "Enable 'service password-encryption'", 1, r_pass_enc, fijo("service password-encryption"), {}, None),
    ("1.4.3", "Set 'username secret' for all local users", 1, r_user_secret, c_usuario, {}, "usuarios"),
    ("1.5.3", "Unset 'public' for 'snmp-server community'", 1, r_snmp_public, fijo("no snmp-server community public"), {}, None),
    ("1.5.5", "Set the ACL for each 'snmp-server community'", 1, r_snmp_acl, c_snmp_acl, {}, None),
    ("1.5.6", "Create an 'access-list' for use with SNMP", 1, r_snmp_acl_existe, c_acl_snmp, {}, None),
    ("1.5.7", "Set 'snmp-server host' when using SNMP", 1, r_snmp_host, fijo("snmp-server host %s version 2c %s" % (KALI, COMUNIDAD_SNMP)), {}, None),
    ("1.5.8", "Set 'snmp-server enable traps snmp'", 1, r_snmp_traps, fijo("snmp-server enable traps snmp authentication linkdown linkup coldstart warmstart"), {}, None),
    ("2.1.1.1.3", "Set 'modulus' >= 2048 for 'crypto key generate rsa'", 1, r_rsa, c_rsa, {}, None),
    ("2.1.1.1.4", "Set 'seconds' for 'ip ssh timeout'", 1, r_ssh_timeout, fijo("ip ssh time-out 60"), {}, None),
    ("2.1.1.1.5", "Set maximum value for 'ip ssh authentication-retries'", 1, r_ssh_retries, fijo("ip ssh authentication-retries 3"), {}, None),
    ("2.1.1.2", "Set version 2 for 'ip ssh version'", 1, r_ssh_v2, fijo("ip ssh version 2"), {}, None),
    ("2.1.2", "Set 'no cdp run'", 1, r_cdp, fijo("no cdp run"), {}, None),
    ("2.1.3", "Set 'no ip bootp server'", 1, r_bootp, fijo("no ip bootp server"), {}, None),
    ("2.1.4", "Set 'no service dhcp'", 1, r_dhcp, fijo("no service dhcp"),
     {"router": "R es el servidor DHCP de la VLAN 10; deshabilitarlo dejaria sin IP a los usuarios"}, None),
    ("2.1.6", "Set 'service tcp-keepalives-in'", 1, r_simple("service tcp-keepalives-in"), fijo("service tcp-keepalives-in"), {}, None),
    ("2.1.7", "Set 'service tcp-keepalives-out'", 1, r_simple("service tcp-keepalives-out"), fijo("service tcp-keepalives-out"), {}, None),
    ("2.1.8", "Set 'no service pad'", 1, r_simple("no service pad"), fijo("no service pad"), {}, None),
    ("2.2.2", "Set 'buffer size' for 'logging buffered'", 1, r_log_buffer, fijo("logging buffered 64000"), {}, None),
    ("2.2.3", "Set 'logging console critical'", 1, r_simple("logging console critical"), fijo("logging console critical"), {}, None),
    ("2.2.4", "Set IP address for 'logging host'", 1, r_log_host, fijo("logging host %s" % KALI), {}, None),
    ("2.2.5", "Set 'logging trap informational'", 1, r_log_trap, fijo("logging trap informational"), {}, None),
    ("2.2.7", "Set 'logging source interface'", 1, r_log_source, lambda d, eq, cred: ["logging source-interface %s" % eq["if_gestion"]], {}, None),
    ("3.1.1", "Set 'no ip source-route'", 1, r_simple("no ip source-route"), fijo("no ip source-route"), {}, None),
    ("3.1.2", "Set 'no ip proxy-arp'", 2, r_proxy_arp, c_interfaces("if_proxy_arp", "no ip proxy-arp"), {}, None),
    ("3.1.4", "Set 'ip verify unicast source reachable-via'", 2, r_urpf, c_interfaces("if_urpf", "ip verify unicast source reachable-via rx"), {}, None),
]


# ---------------------------------------------------------------------------
# FortiGate (CIS FortiGate 7.0.x Benchmark v1.3.0)
# Se leen salidas 'get' (muestran todos los valores, incluidos los por defecto)
# y 'show' (solo lo configurado) para no depender de un grep superficial.
# ---------------------------------------------------------------------------
def valores_get(texto):
    """Convierte la salida de un 'get' de FortiOS ('clave : valor') en diccionario."""
    d = {}
    for linea in texto.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_\-]+)\s*:\s*(.*?)\s*$", linea)
        if m and m.group(1) not in d:
            d[m.group(1)] = m.group(2)
    return d


def bloques_edit(texto):
    """Devuelve {nombre: bloque} de una salida 'show' de FortiOS (edit "x" ... next)."""
    res, actual, nombre = {}, [], None
    for linea in texto.splitlines():
        m = re.match(r'^\s*edit\s+"?([^"]+?)"?\s*$', linea)
        if m:
            nombre, actual = m.group(1), []
            continue
        if re.match(r"^\s*next\s*$", linea) and nombre is not None:
            res[nombre] = "\n".join(actual)
            nombre = None
            continue
        if nombre is not None:
            actual.append(linea)
    return res


def fg_valor(d, eq, seccion, clave):
    return valores_get(d[seccion]).get(clave, "")


def fg_global(clave, esperado):
    def f(d, eq):
        v = fg_valor(d, eq, "global", clave)
        if not v:
            return None, "'%s' no existe en esta version de FortiOS" % clave
        return v == esperado, "%s: %s" % (clave, v)
    return f


def fg_allowaccess(d, eq, interfaz):
    b = bloques_edit(d["interfaces"]).get(interfaz, "")
    m = re.search(r"set allowaccess (.+)", b)
    return m.group(1).split() if m else []


def r_fg_wan(d, eq):
    acc = fg_allowaccess(d, eq, eq["if_wan"])
    return not acc, "allowaccess %s: %s" % (eq["if_wan"], " ".join(acc) or "ninguno")


def r_fg_cifrado(d, eq):
    acc = fg_allowaccess(d, eq, eq["if_lan"])
    inseguros = [s for s in acc if s in ("http", "telnet")]
    return not inseguros, "allowaccess %s: %s" % (eq["if_lan"], " ".join(acc) or "ninguno")


def r_fg_hostname(d, eq):
    v = fg_valor(d, eq, "global", "hostname")
    return bool(v) and not v.startswith("FortiGate-"), "hostname: %s" % (v or "?")


def r_fg_usb(d, eq):
    a = valores_get(d["autoinstall"])
    ok = a.get("auto-install-config") == "disable" and a.get("auto-install-image") == "disable"
    return ok, "auto-install-config: %s / auto-install-image: %s" % (a.get("auto-install-config", "?"), a.get("auto-install-image", "?"))


def r_fg_tls_gui(d, eq):
    v = fg_valor(d, eq, "global", "admin-https-ssl-versions")
    if not v:
        return None, "'admin-https-ssl-versions' no existe en esta version"
    viejos = [x for x in v.split() if x in ("tlsv1-0", "tlsv1-1")]
    return not viejos, "admin-https-ssl-versions: %s" % v


def r_fg_pass_policy(d, eq):
    p = valores_get(d["passpolicy"])
    ok = p.get("status") == "enable" and int(p.get("minimum-length", "0") or 0) >= 8
    return ok, "status: %s, minimum-length: %s" % (p.get("status", "?"), p.get("minimum-length", "?"))


def r_fg_lockout(d, eq):
    g = valores_get(d["global"])
    th, du = g.get("admin-lockout-threshold", "0"), g.get("admin-lockout-duration", "0")
    ok = 0 < int(th or 0) <= 3 and int(du or 0) >= 900
    return ok, "threshold: %s, duration: %s s" % (th, du)


def r_fg_trusthost(d, eq):
    admins = bloques_edit(d["admins"])
    if not admins:
        return False, "No se pudieron leer los administradores"
    sin = [a for a, b in admins.items() if not re.search(r"set trusthost\d+ (?!0\.0\.0\.0 0\.0\.0\.0)", b)]
    return not sin, "Sin trusted hosts: " + ", ".join(sin) if sin else "Todos los admins con trusted hosts"


def r_fg_timeout(d, eq):
    v = fg_valor(d, eq, "global", "admintimeout")
    return bool(v) and 0 < int(v) <= 5, "admintimeout: %s min" % (v or "?")


def r_fg_servicio_all(d, eq):
    pol = bloques_edit(d["politicas"])
    malas = [p for p, b in pol.items() if re.search(r'set service .*"ALL"', b)]
    return not malas, "Politicas con service ALL: " + ", ".join(malas) if malas else "Ninguna politica usa ALL"


def r_fg_log_politicas(d, eq):
    pol = bloques_edit(d["politicas"])
    if not pol:
        return None, "No hay politicas"
    sin = [p for p, b in pol.items() if "set logtraffic all" not in b]
    return not sin, "Sin logtraffic all: " + ", ".join(sin) if sin else "Todas las politicas registran trafico"


def r_fg_eventos(d, eq):
    v = valores_get(d["eventfilter"]).get("event", "")
    return v == "enable", "event: %s" % (v or "?")


def r_fg_syslog(d, eq):
    s = valores_get(d["syslog"])
    ok = s.get("status") == "enable" and s.get("server") == KALI
    return ok, "status: %s, server: %s" % (s.get("status", "?"), s.get("server", "?"))


def fg_bloque(*lineas):
    return lambda d, eq, cred: list(lineas)


def c_fg_wan(d, eq, cred):
    return ["config system interface", "edit %s" % eq["if_wan"], "unset allowaccess", "next", "end"]


def c_fg_lan(d, eq, cred):
    return ["config system interface", "edit %s" % eq["if_lan"], "set allowaccess https ssh", "next", "end",
            "config system global", "set admin-https-redirect enable", "end"]


def c_fg_trusthost(d, eq, cred):
    cmds = ["config system admin"]
    for a in bloques_edit(d["admins"]):
        cmds += ["edit %s" % a, "set trusthost1 %s %s" % (RED_GESTION, MASCARA_GESTION), "next"]
    return cmds + ["end"]


def c_fg_politicas(campo, linea):
    def f(d, eq, cred):
        cmds = ["config firewall policy"]
        for p, b in bloques_edit(d["politicas"]).items():
            if campo == "service" and not re.search(r'set service .*"ALL"', b):
                continue
            cmds += ["edit %s" % p, linea, "next"]
        return cmds + ["end"]
    return f


REGLAS_FW = [
    ("1.3", "Ensure all management related services are disabled on WAN port", 1, r_fg_wan, c_fg_wan, {}, None),
    ("2.1.1", "Ensure 'Pre-Login Banner' is set", 1, fg_global("pre-login-banner", "enable"),
     fg_bloque("config system global", "set pre-login-banner enable", "end"), {}, None),
    ("2.1.2", "Ensure 'Post-Login Banner' is set", 1, fg_global("post-login-banner", "enable"),
     fg_bloque("config system global", "set post-login-banner enable", "end"), {}, None),
    ("2.1.5", "Ensure hostname is set", 1, r_fg_hostname, fg_bloque("config system global", "set hostname FW", "end"), {}, None),
    ("2.1.7", "Disable USB Firmware and configuration installation", 1, r_fg_usb,
     fg_bloque("config system auto-install", "set auto-install-config disable", "set auto-install-image disable", "end"), {}, None),
    ("2.1.8", "Disable static keys for TLS", 1, fg_global("ssl-static-key-ciphers", "disable"),
     fg_bloque("config system global", "set ssl-static-key-ciphers disable", "end"), {}, None),
    ("2.1.9", "Enable Global Strong Encryption", 1, fg_global("strong-crypto", "enable"),
     fg_bloque("config system global", "set strong-crypto enable", "end"), {}, None),
    ("2.1.10", "Ensure management GUI listens on secure TLS version", 1, r_fg_tls_gui,
     fg_bloque("config system global", "set admin-https-ssl-versions tlsv1-2 tlsv1-3", "end"), {}, None),
    ("2.2.1", "Ensure 'Password Policy' is enabled", 1, r_fg_pass_policy,
     fg_bloque("config system password-policy", "set status enable", "set apply-to admin-password",
               "set minimum-length 8", "set min-lower-case-letter 1", "set min-upper-case-letter 1",
               "set min-number 1", "set min-non-alphanumeric 1", "end"), {}, None),
    ("2.2.2", "Ensure administrator password retries and lockout time are configured", 1, r_fg_lockout,
     fg_bloque("config system global", "set admin-lockout-threshold 3", "set admin-lockout-duration 900", "end"), {}, None),
    ("2.4.2", "Ensure all the login accounts having specific trusted hosts enabled", 1, r_fg_trusthost, c_fg_trusthost, {}, None),
    ("2.4.4", "Ensure idle timeout time is configured", 1, r_fg_timeout,
     fg_bloque("config system global", "set admintimeout 5", "end"), {}, None),
    ("2.4.5", "Ensure only encrypted access channels are enabled", 1, r_fg_cifrado, c_fg_lan, {}, None),
    ("3.2", "Ensure that policies do not use 'ALL' as Service", 1, r_fg_servicio_all,
     c_fg_politicas("service", "set service " + SERVICIOS_SALIDA), {}, None),
    ("3.4", "Ensure logging is enabled on all firewall policies", 1, r_fg_log_politicas,
     c_fg_politicas("log", "set logtraffic all"), {}, None),
    ("7.1.1", "Enable Event Logging", 1, r_fg_eventos, fg_bloque("config log eventfilter", "set event enable", "end"), {}, None),
    ("7.3.1", "Centralized Logging and Reporting (syslog)", 1, r_fg_syslog,
     lambda d, eq, cred: ["config log syslogd setting", "set status enable", "set server %s" % KALI,
                          "set mode udp", "set port 514", "set source-ip %s" % eq["ip_lan"], "end"], {}, None),
]


def reglas_de(eq):
    return REGLAS_FW if eq["device_type"] == "fortinet" else REGLAS


# ---------------------------------------------------------------------------
# Conexion, recoleccion y auditoria
# ---------------------------------------------------------------------------
def conectar(eq, cred, clave, enable):
    conn = ConnectHandler(device_type=eq["device_type"], host=eq["ip"], username=cred["usuario"],
                          password=clave, secret=enable, conn_timeout=20, fast_cli=False)
    if eq["device_type"] == "cisco_ios":
        conn.enable()
    return conn


def recolectar(conn, eq):
    if eq["device_type"] == "fortinet":
        return {
            "run": conn.send_command("show", read_timeout=180),
            "global": conn.send_command("get system global", read_timeout=60),
            "interfaces": conn.send_command("show system interface", read_timeout=60),
            "admins": conn.send_command("show system admin", read_timeout=60),
            "autoinstall": conn.send_command("get system auto-install"),
            "passpolicy": conn.send_command("get system password-policy"),
            "politicas": conn.send_command("show firewall policy", read_timeout=60),
            "eventfilter": conn.send_command("get log eventfilter"),
            "syslog": conn.send_command("get log syslogd setting"),
        }
    return {
        "run": conn.send_command("show running-config", read_timeout=90),
        "ssh": conn.send_command("show ip ssh"),
        "cdp": conn.send_command("show cdp"),
        "logging": conn.send_command("show logging | include Trap logging"),
        "rsa": conn.send_command("show crypto key mypubkey rsa", read_timeout=60),
    }


def auditar(d, eq):
    resultados = []
    for rid, titulo, nivel, verificar, _c, excepciones, _g in reglas_de(eq):
        if eq["tipo"] in excepciones:
            resultados.append((rid, titulo, nivel, EXCEPCION, excepciones[eq["tipo"]]))
            continue
        try:
            ok, evidencia = verificar(d, eq)
        except Exception as e:                       # una regla rota no detiene la auditoria
            ok, evidencia = False, "Error al verificar: %s" % e
        estado = NA if ok is None else (CUMPLE if ok else NO_CUMPLE)
        resultados.append((rid, titulo, nivel, estado, evidencia))
    return resultados


def guardar_config(eq, run, fase, sello):
    os.makedirs(DIR_CONFIGS, exist_ok=True)
    ruta = os.path.join(DIR_CONFIGS, "%s_running-config_%s_%s.txt" % (eq["nombre"], fase, sello))
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(run)
    return ruta


def ejecutar(conn, comandos, eq):
    """Envia los comandos respondiendo confirmaciones (IOS en modo config; FortiOS directo)."""
    advertencias = []
    cisco = eq["device_type"] == "cisco_ios"
    if cisco:
        conn.config_mode()
    for c in comandos:
        if isinstance(c, dict):
            cmd, resp, espera = c["cmd"], c.get("confirmar"), c.get("espera", 2)
        else:
            cmd, resp, espera = c, None, 1
        salida = conn.send_command_timing(cmd, strip_prompt=False, strip_command=False,
                                          last_read=espera, read_timeout=120)
        if resp is not None and ("[confirm]" in salida or "yes/no" in salida.lower()):
            salida += conn.send_command_timing(resp, strip_prompt=False, strip_command=False,
                                               last_read=espera, read_timeout=120)
        if re.search(r"% ?(Invalid|Incomplete|Ambiguous)|ERROR|command parse error|Unknown action|"
                     r"value parse error|entry not found|Command fail", salida):
            advertencias.append("%s -> %s" % (cmd, salida.strip().splitlines()[-1] if salida.strip() else ""))
    if cisco:
        conn.exit_config_mode()
    return advertencias


def quitar_repetidos(cmds):
    """Quita comandos globales y bloques de ACL repetidos (las lineas/interfaces se dejan)."""
    vistos, salida, saltar = set(), [], False
    for c in cmds:
        texto = c["cmd"] if isinstance(c, dict) else c
        if saltar:
            if texto.startswith(" "):
                continue
            saltar = False
        if texto.startswith("ip access-list "):
            if texto in vistos:
                saltar = True
                continue
            vistos.add(texto)
        elif not texto.startswith((" ", "line ", "interface ")) and not isinstance(c, dict):
            if texto in vistos:
                continue
            vistos.add(texto)
        salida.append(c)
    return salida


def comandos_a_aplicar(d, eq, cred, resultados):
    cmds, grupos = [], set()
    fallidas = {r[0] for r in resultados if r[3] == NO_CUMPLE}
    for rid, _t, _n, _v, corregir, _e, grupo in reglas_de(eq):
        if rid not in fallidas:
            continue
        if grupo:
            if grupo in grupos:
                continue
            grupos.add(grupo)
        cmds += corregir(d, eq, cred)
    # En FortiOS los bloques "config ... end" van completos, no se deduplican lineas
    return cmds if eq["device_type"] == "fortinet" else quitar_repetidos(cmds)


# ---------------------------------------------------------------------------
# Informes
# ---------------------------------------------------------------------------
def resumen(resultados):
    return {e: sum(1 for r in resultados if r[3] == e) for e in (CUMPLE, NO_CUMPLE, EXCEPCION, NA)}


def imprimir(eq, resultados, titulo):
    print("\n" + "=" * 100)
    print(" %s - %s (%s)" % (titulo, eq["nombre"], eq["ip"]))
    print("=" * 100)
    for rid, t, nivel, estado, ev in resultados:
        print(" %-10s %-58s L%-2s %-10s" % (rid, t[:58], nivel, estado))
    s = resumen(resultados)
    print("-" * 100)
    print(" Cumple: %d | No cumple: %d | Excepcion: %d | N/A: %d" % (s[CUMPLE], s[NO_CUMPLE], s[EXCEPCION], s[NA]))


def informe_html(datos, titulo, sello, extra=""):
    os.makedirs(DIR_REPORTES, exist_ok=True)
    colores = {CUMPLE: "#1e7e34", NO_CUMPLE: "#c0392b", EXCEPCION: "#b8860b", NA: "#6c757d"}
    partes = []
    for eq, resultados, notas in datos:
        s = resumen(resultados)
        filas = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td style='color:%s;font-weight:bold'>%s</td><td>%s</td></tr>"
            % (html.escape(r[0]), html.escape(r[1]), r[2], colores[r[3]], r[3], html.escape(str(r[4])))
            for r in resultados)
        lista_notas = "".join("<li>%s</li>" % html.escape(n) for n in notas)
        partes.append(
            "<h2>%s (%s) - %s</h2>"
            "<p><b>Cumple:</b> %d &nbsp; <b>No cumple:</b> %d &nbsp; <b>Excepcion:</b> %d &nbsp; <b>N/A:</b> %d</p>"
            "<table><tr><th>CIS</th><th>Control</th><th>Nivel</th><th>Estado</th><th>Evidencia</th></tr>%s</table>%s"
            % (eq["nombre"], eq["ip"], eq["tipo"], s[CUMPLE], s[NO_CUMPLE], s[EXCEPCION], s[NA], filas,
               "<ul>%s</ul>" % lista_notas if notas else ""))
    pagina = ("<!doctype html><html lang='es'><head><meta charset='utf-8'><title>%s</title>"
              "<style>body{font-family:Arial,sans-serif;margin:24px;color:#222}"
              "table{border-collapse:collapse;width:100%%;margin-bottom:20px}"
              "th,td{border:1px solid #ccc;padding:6px;font-size:13px;text-align:left}"
              "th{background:#f0f0f0}</style></head><body>"
              "<h1>%s</h1><p>CIS Cisco IOS 15 Benchmark v4.1.1 (R, SW) y CIS FortiGate 7.0.x Benchmark v1.3.0 (FW)"
              " - Generado: %s</p>%s%s</body></html>"
              % (titulo, titulo, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), extra, "".join(partes)))
    nombre = re.sub(r"[^a-z0-9]+", "_", titulo.lower()).strip("_")
    ruta = os.path.join(DIR_REPORTES, "%s_%s.html" % (nombre, sello))
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(pagina)
    return ruta


# ---------------------------------------------------------------------------
# Programa principal
# ---------------------------------------------------------------------------
def pedir_nueva(texto):
    """Pide una contrasena nueva dos veces (Enter = mantener la actual)."""
    while True:
        p1 = getpass.getpass("%s [Enter = mantener]: " % texto)
        if not p1:
            return ""
        if getpass.getpass("Repite la contrasena: ") == p1:
            return p1
        print("[!] No coinciden, intenta de nuevo.")


def claves(eq, cred, despues=False):
    """Devuelve (clave, enable) para conectarse a un equipo antes o despues de aplicar."""
    if eq["device_type"] == "fortinet":
        return cred["clave_fw"], ""
    if despues:
        return cred["nueva_clave"], cred["nuevo_enable"]
    return cred["clave"], cred["enable"]


def main():
    p = argparse.ArgumentParser(description="Auditoria y hardening CIS (R y SW Cisco IOS 15, FW FortiGate 7.0)")
    modo = p.add_mutually_exclusive_group(required=True)
    modo.add_argument("--auditar", action="store_true", help="Generar informe sin aplicar reglas")
    modo.add_argument("--aplicar", action="store_true", help="Aplicar reglas y generar informe posterior")
    p.add_argument("--equipo", choices=[e["nombre"] for e in EQUIPOS], help="Trabajar solo con un equipo")
    p.add_argument("--usuario", default="admin", help="Usuario SSH (por defecto: admin)")
    p.add_argument("--si", action="store_true", help="No pedir confirmacion antes de aplicar")
    a = p.parse_args()

    equipos = [e for e in EQUIPOS if not a.equipo or e["nombre"] == a.equipo]
    hay_cisco = any(e["device_type"] == "cisco_ios" for e in equipos)
    hay_fw = any(e["device_type"] == "fortinet" for e in equipos)
    cred = {"usuario": a.usuario}
    if hay_cisco:
        cred["clave"] = getpass.getpass("Contrasena SSH de '%s' en R/SW: " % a.usuario)
        cred["enable"] = getpass.getpass("Contrasena de enable en R/SW: ")
    if hay_fw:
        cred["clave_fw"] = getpass.getpass("Contrasena de '%s' en el FortiGate: " % a.usuario)
    if a.aplicar:
        if hay_cisco:
            cred["nueva_clave"] = pedir_nueva("Nueva contrasena (secret) para '%s' en R/SW" % a.usuario) or cred["clave"]
            cred["nuevo_enable"] = pedir_nueva("Nuevo enable secret en R/SW") or cred["enable"]
        if not a.si:
            r = input("\nSe aplicaran cambios en %s. Escribe SI para continuar: " % ", ".join(e["nombre"] for e in equipos))
            if r.strip().upper() != "SI":
                print("Cancelado.")
                return

    sello = datetime.now().strftime("%Y%m%d_%H%M%S")
    previos, posteriores = [], []

    for eq in equipos:
        print("\n[*] Conectando a %s (%s)..." % (eq["nombre"], eq["ip"]))
        try:
            conn = conectar(eq, cred, *claves(eq, cred))
        except Exception as e:
            print("[!] No se pudo conectar a %s: %s" % (eq["nombre"], e))
            continue

        d = recolectar(conn, eq)
        res = auditar(d, eq)
        fase = "auditoria" if a.auditar else "antes"
        ruta_cfg = guardar_config(eq, d["run"], fase, sello)
        imprimir(eq, res, "INFORME DE AUDITORIA" if a.auditar else "ESTADO PREVIO")
        print("[+] Running-config guardado en %s" % ruta_cfg)
        previos.append((eq, res, []))

        if a.auditar:
            conn.disconnect()
            continue

        cmds = comandos_a_aplicar(d, eq, cred, res)
        notas = []
        if not cmds:
            print("[=] %s ya cumple todas las reglas elegidas." % eq["nombre"])
        else:
            print("[*] Aplicando %d comandos en %s..." % (len(cmds), eq["nombre"]))
            notas = ejecutar(conn, cmds, eq)
            if eq["device_type"] == "cisco_ios":
                conn.save_config()
                print("[+] Configuracion guardada (write memory).")
            else:
                print("[+] FortiOS guarda la configuracion automaticamente al cerrar cada bloque (end).")
            for n in notas:
                print("[!] Advertencia: %s" % n)
        conn.disconnect()

        print("[*] Reconectando a %s para la auditoria posterior..." % eq["nombre"])
        time.sleep(3)
        try:
            conn = conectar(eq, cred, *claves(eq, cred, despues=True))
        except Exception as e:
            print("[!] No se pudo reconectar a %s: %s" % (eq["nombre"], e))
            continue
        d2 = recolectar(conn, eq)
        res2 = auditar(d2, eq)
        ruta_cfg2 = guardar_config(eq, d2["run"], "despues", sello)
        conn.disconnect()
        imprimir(eq, res2, "ESTADO POSTERIOR")
        print("[+] Running-config guardado en %s" % ruta_cfg2)
        posteriores.append((eq, res2, notas))

    if a.auditar and previos:
        print("\n[+] Informe: %s" % informe_html(previos, "Informe de auditoria CIS", sello))
    if a.aplicar and previos:
        print("\n[+] Informe previo: %s" % informe_html(previos, "Informe CIS previo al hardening", sello))
        if posteriores:
            print("[+] Informe posterior: %s" % informe_html(posteriores, "Informe CIS posterior al hardening", sello))


if __name__ == "__main__":
    main()
