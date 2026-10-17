#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rutas_estaticas.py — DEMO de rutas estáticas MikroTik <-> Cisco (ITIEL-13 · Lab 1)

TOPOLOGÍA
    PC1 --(172.16.10.0/24, gw .1)-- Cisco Fa1/0     [.203 en 10.60.30.0/24]
    PC2 --(172.16.20.0/24, gw .1)-- MikroTik ether8 [.202 en 10.60.30.0/24]
    Interconexión (transit): 10.60.30.0/24 (gateway .1)

EL PROBLEMA
    Cada router solo conoce su propia LAN. Todo lo demás lo manda al gateway
    10.60.30.1, que no sabe nada de las redes 172.16.x, así que el ping se pierde.

LA SOLUCIÓN
    - Ruta estática en cada router hacia la LAN del otro.
    - Excepción de NAT: no enmascarar el tráfico entre las dos LAN
      (el NAT queda solo para salir a Internet).
    Todo es idempotente: consultar -> ¿ya existe? -> crear solo si falta.
    Por eso la segunda ejecución dice "sin cambios".

USO
    python rutas_estaticas.py             # aplica y prueba el ping
    python rutas_estaticas.py --estado    # solo mira (no cambia nada)
    python rutas_estaticas.py --limpiar   # deshace los cambios

CREDENCIALES
    Nunca en el código: se leen de las variables LAB_PASS_MT_LAB y
    LAB_PASS_CISCO_LAB (compatibles con LAB_PASS_MIKROTIK / LAB_PASS_CISCO);
    si no existen, se piden por consola con getpass.
"""
import argparse
import getpass
import ipaddress
import os
import sys

import yaml

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except Exception:
    ConnectHandler = None
    NetmikoTimeoutException = Exception
    NetmikoAuthenticationException = Exception


# --- 2) Datos de la topología (constantes) -----------------------------------
LAN_CISCO = "172.16.10.0/24"     # LAN de PC1 (detrás del Cisco)
LAN_MT = "172.16.20.0/24"        # LAN de PC2 (detrás del MikroTik)
GW_PC1 = "172.16.10.1"           # gateway de PC1 (Cisco Fa1/0)
GW_PC2 = "172.16.20.1"           # gateway de PC2 (MikroTik ether8)
ETIQUETA = "RUTAS-LAB"           # firma: todo lo que crea el script lleva esto

IFACE_WAN_CISCO = "Fa0/0"        # interfaz del Cisco hacia Internet (NAT outside)
NAT_LISTA_BASE = "10"            # ACL previa que este lab reemplaza por NAT-PC1


# --- 3) Funciones ayudantes ---------------------------------------------------
def clave(variable, texto):
    """Contraseña desde el entorno; si no existe, la pide sin mostrarla."""
    return os.getenv(variable) or getpass.getpass(texto)


def equipo(inventario, device_type):
    """Devuelve los datos del equipo del inventario según su device_type.

    Acepta el formato nuevo ({'equipos': [ {...}, ... ]}) y el antiguo
    ({'mikrotik': {...}, 'cisco': {...}}).
    """
    for datos in _lista_equipos(inventario):
        if datos.get("device_type") == device_type:
            return datos
    raise KeyError(f"No hay ningún equipo con device_type={device_type} en el inventario")


def _lista_equipos(inventario):
    """Normaliza el YAML a una lista de equipos."""
    if isinstance(inventario, dict) and isinstance(inventario.get("equipos"), list):
        return inventario["equipos"]
    if isinstance(inventario, dict):
        # Formato antiguo: cada clave es el nombre del equipo.
        return [dict(valor, nombre=clave) for clave, valor in inventario.items()]
    raise ValueError("inventario.yaml: se esperaba un diccionario con 'equipos'")


def conexion(datos, password):
    """Arma el diccionario de parámetros que espera ConnectHandler."""
    d = dict(datos)
    d["username"] = d.get("username") or d.pop("usuario", None)
    for campo in ("nombre", "rol"):
        d.pop(campo, None)
    d["password"] = password
    d.setdefault("conn_timeout", 20)
    d.setdefault("fast_cli", False)
    return d


def clave(*variables, texto):
    """Contraseña desde el entorno (en orden); si no existe, la pide sin mostrarla."""
    for variable in variables:
        valor = os.getenv(variable)
        if valor:
            return valor
    return getpass.getpass(texto)


def mascara(cidr):
    """'172.16.20.0/24' -> ('172.16.20.0', '255.255.255.0')  (Cisco, ruta)."""
    red = ipaddress.ip_network(cidr, strict=False)
    return str(red.network_address), str(red.netmask)


def wildcard(cidr):
    """'172.16.10.0/24' -> ('172.16.10.0', '0.0.0.255')  (Cisco, ACL)."""
    red = ipaddress.ip_network(cidr, strict=False)
    return str(red.network_address), str(red.hostmask)


def _indent(texto):
    return "\n".join("    " + l for l in (texto or "").splitlines())


def _marca(ok):
    return "[APLICADO   ]" if ok else "[NO aplicado]"


# --- 4) MikroTik --------------------------------------------------------------
def _mt_len(conn, find):
    """Cuenta elementos: :put [:len [/algo find ...]]  ->  '0' = no existe."""
    out = conn.send_command(f':put [:len [{find}]]').strip()
    return int(out) if out.isdigit() else 0


def mikrotik(conn, cisco_ip):
    """Crea la ruta hacia la LAN del Cisco y la excepción de NAT (idempotente)."""
    find_ruta = f'/ip route find comment="{ETIQUETA}" dst-address={LAN_CISCO}'
    if _mt_len(conn, find_ruta) == 0:
        conn.send_config_set([
            f'/ip route add dst-address={LAN_CISCO} gateway={cisco_ip} comment="{ETIQUETA}"',
        ])
        print(f"[+] MikroTik: ruta {LAN_CISCO} via {cisco_ip}")
    else:
        print(f"[=] MikroTik: ruta {LAN_CISCO} ya existe (sin cambios)")

    find_nat = f'/ip firewall nat find comment="{ETIQUETA}"'
    if _mt_len(conn, find_nat) == 0:
        # Se agrega y luego se sube al tope: el NAT se lee de arriba hacia abajo
        # y el primer match gana, así que la excepción debe ir antes del masquerade.
        conn.send_config_set([
            f'/ip firewall nat add chain=srcnat src-address={LAN_MT} '
            f'dst-address={LAN_CISCO} action=accept comment="{ETIQUETA}"',
        ])
        conn.send_command(f'/ip firewall nat move [find comment="{ETIQUETA}"] destination=0')
        print(f"[+] MikroTik: excepción NAT {LAN_MT} -> {LAN_CISCO}")
    else:
        print(f"[=] MikroTik: excepción NAT ya existe (sin cambios)")


def mikrotik_estado(conn, cisco_ip):
    hay_ruta = _mt_len(conn, f'/ip route find comment="{ETIQUETA}" dst-address={LAN_CISCO}') > 0
    hay_nat = _mt_len(conn, f'/ip firewall nat find comment="{ETIQUETA}"') > 0
    print(f"{_marca(hay_ruta)} (MikroTik) Ruta {LAN_CISCO} via {cisco_ip}")
    print(f"{_marca(hay_nat)} (MikroTik) Excepción NAT {LAN_MT} -> {LAN_CISCO}")
    print("  Rutas actuales (/ip route print terse):")
    print(_indent(conn.send_command("/ip route print terse")))
    print("  NAT actual, en orden (/ip firewall nat print):")
    print(_indent(conn.send_command("/ip firewall nat print")))


def mikrotik_limpiar(conn):
    """Borra solo lo que creó el script (todo lo firmado con ETIQUETA)."""
    conn.send_config_set([f'/ip route remove [find comment="{ETIQUETA}"]'])
    conn.send_config_set([f'/ip firewall nat remove [find comment="{ETIQUETA}"]'])
    print("[OK] MikroTik: ruta y NAT eliminados")


# --- 5) Cisco -----------------------------------------------------------------
def _cs_hay_ruta(conn):
    return ETIQUETA in conn.send_command("show running-config | include ip route")


def _cs_nat_actual(conn):
    """Líneas 'ip nat inside source ...' que hoy tiene el Cisco."""
    salida = conn.send_command("show running-config | include ip nat inside source")
    return [l.strip() for l in salida.splitlines() if l.strip().startswith("ip nat inside source")]


def _cs_hay_nat(conn):
    return any("NAT-PC1" in l for l in _cs_nat_actual(conn))


def cisco(conn, mt_ip):
    """Ruta hacia la LAN del MikroTik + ACL extendida de NAT (idempotente)."""
    conn.enable()
    red_mt, mask_mt = mascara(LAN_MT)
    addr_cs, wc_cs = wildcard(LAN_CISCO)
    addr_mt, wc_mt = wildcard(LAN_MT)

    if not _cs_hay_ruta(conn):
        conn.send_config_set([f"ip route {red_mt} {mask_mt} {mt_ip} name {ETIQUETA}"])
        print(f"[+] Cisco: ruta {LAN_MT} via {mt_ip}")
    else:
        print(f"[=] Cisco: ruta {LAN_MT} ya existe (sin cambios)")

    if not _cs_hay_nat(conn):
        cmds = [
            "ip access-list extended NAT-PC1",
            f" deny ip {addr_cs} {wc_cs} {addr_mt} {wc_mt}",
            f" permit ip {addr_cs} {wc_cs} any",
            "exit",
        ]
        # IOS solo admite un 'ip nat inside source list ... overload': si ya hay
        # uno (la ACL base), hay que quitarlo antes de poner el nuestro.
        for linea in _cs_nat_actual(conn):
            cmds.append("no " + linea)
        cmds.append(f"ip nat inside source list NAT-PC1 interface {IFACE_WAN_CISCO} overload")
        conn.send_config_set(cmds)
        print(f"[+] Cisco: excepción NAT NAT-PC1 ({LAN_CISCO} -> {LAN_MT})")
    else:
        print("[=] Cisco: excepción NAT ya existe (sin cambios)")


def cisco_estado(conn, mt_ip):
    conn.enable()
    print(f"{_marca(_cs_hay_ruta(conn))} (Cisco) Ruta {LAN_MT} via {mt_ip}")
    print(f"{_marca(_cs_hay_nat(conn))} (Cisco) Excepción NAT {LAN_CISCO} -> {LAN_MT}")
    print("  Rutas actuales (show ip route static):")
    print(_indent(conn.send_command("show ip route static")))
    print("  NAT actual, en orden (show run | include ip nat inside source):")
    print(_indent(conn.send_command("show running-config | include ip nat inside source")))


def cisco_limpiar(conn, mt_ip):
    """Quita la ruta y la excepción NAT y restaura la ACL base."""
    conn.enable()
    red_mt, mask_mt = mascara(LAN_MT)
    cmds = [f"no ip route {red_mt} {mask_mt} {mt_ip}"]
    if _cs_hay_nat(conn):
        cmds.append("no ip access-list extended NAT-PC1")
        for linea in _cs_nat_actual(conn):
            if "NAT-PC1" in linea:
                cmds.append("no " + linea)
        cmds.append(f"ip nat inside source list {NAT_LISTA_BASE} "
                    f"interface {IFACE_WAN_CISCO} overload")
    conn.send_config_set(cmds)
    print("[OK] Cisco: ruta y NAT restaurados")


# --- 6) Ping gateway a gateway ------------------------------------------------
def ping_mikrotik(conn, cisco_ip):
    print(f"  ping MikroTik -> Cisco ({cisco_ip}):")
    print(_indent(conn.send_command(f"/ping {cisco_ip} count=3", read_timeout=30)))


def ping_cisco(conn, mt_ip):
    print(f"  ping Cisco -> MikroTik ({mt_ip}):")
    print(_indent(conn.send_command(f"ping {mt_ip} repeat 3", read_timeout=30)))


# --- 7) main(): el director de orquesta --------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="DEMO rutas estáticas MikroTik <-> Cisco (ITIEL-13 · Lab 1)",
    )
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument("--limpiar", action="store_true", help="deshace los cambios")
    modo.add_argument("--estado", action="store_true", help="solo mira, no cambia nada")
    parser.add_argument("--inventario", default="inventario.yaml", help="ruta del inventario YAML")
    args = parser.parse_args()

    if ConnectHandler is None:
        print("ERROR: netmiko no está instalado (pip install -r requirements.txt)", file=sys.stderr)
        sys.exit(1)

    with open(args.inventario, "r", encoding="utf-8") as f:
        inventario = yaml.safe_load(f)

    datos_mt = equipo(inventario, "mikrotik_routeros")
    datos_cs = equipo(inventario, "cisco_ios")
    mt_ip = datos_mt["host"]
    cs_ip = datos_cs["host"]

    conn_mt = conexion(
        datos_mt,
        clave("LAB_PASS_MT_LAB", "LAB_PASS_MIKROTIK", texto="Contraseña del MikroTik: "),
    )
    conn_cs = conexion(
        datos_cs,
        clave("LAB_PASS_CISCO_LAB", "LAB_PASS_CISCO", texto="Contraseña del Cisco: "),
    )
    # lab-ssh entra con privilegio 1: para configurar hace falta 'enable'.
    conn_cs["secret"] = (
        os.getenv("LAB_SECRET_CISCO_LAB") or os.getenv("LAB_SECRET_CISCO") or conn_cs["password"]
    )

    try:
        with ConnectHandler(**conn_mt) as c_mt, ConnectHandler(**conn_cs) as c_cs:
            if args.estado:
                mikrotik_estado(c_mt, cs_ip)
                cisco_estado(c_cs, mt_ip)
                return

            if args.limpiar:
                mikrotik_limpiar(c_mt)
                cisco_limpiar(c_cs, mt_ip)
                print("[OK] Laboratorio restaurado al estado inicial")
                return

            mikrotik(c_mt, cs_ip)
            cisco(c_cs, mt_ip)

            # Recién ahora, con la ida y la vuelta configuradas, se prueba:
            ping_mikrotik(c_mt, cs_ip)
            ping_cisco(c_cs, mt_ip)
            print(f"En GNS3:  PC1> ping {GW_PC2}     PC2> ping {GW_PC1}")
    except NetmikoTimeoutException as e:
        print(f"ERROR: timeout al conectar ({e})", file=sys.stderr)
        sys.exit(1)
    except NetmikoAuthenticationException as e:
        print(f"ERROR: autenticación fallida ({e})", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
