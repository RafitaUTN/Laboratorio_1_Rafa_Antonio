#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lab1_inventario.py — Laboratorio 1 ITIEL-13 (III-2026)

Inventario, estado y configuración segura con Python + SSH (Netmiko).

Qué hace
    1. Carga inventario.yaml (equipos FUERA del código, SIN contraseñas).
    2. Pide cada contraseña por variable de entorno LAB_PASS_<NOMBRE> o getpass.
    3. Se conecta por SSH con ConnectHandler (bloque with) a cada equipo.
    4. Recolecta estado y lo convierte a diccionarios (no texto crudo).
    5. Genera reporte_estado.json y una tabla resumen en consola.
    6. Solo en equipos con rol=escritura (MikroTik): asegura de forma
       IDEMPOTENTE la interfaz lo-ssh-<N> (bridge sin puertos) con la IP
       10.253.0.<N>/32 y un comentario identificador del laboratorio.
    7. EXTRA (+10): el mismo MikroTik puede consultarse por su API REST
       (/rest, JSON sobre HTTPS autofirmado) si el inventario lo define así,
       de modo que SSH y REST conviven en el mismo inventario.

Topología (laboratorio GNS3, red 10.60.30.0/24, gw .1)
    MikroTik RouterOS v7  10.60.30.202  rol: escritura  usuario: lab-ssh
    Cisco IOS 3725        10.60.30.203  rol: lectura    usuario: lab-ssh

Uso
    python lab1_inventario.py                 # estado + config idempotente
    python lab1_inventario.py --estado        # SOLO consulta (nada se cambia)
    python lab1_inventario.py --limpiar       # borra SOLO los objetos propios
    python lab1_inventario.py --n 5           # número de lista del estudiante
    LAB_N=5 python lab1_inventario.py         # idem, por variable de entorno

Reglas de seguridad
    - Ninguna contraseña en el código, el YAML, el reporte ni los logs.
    - El laboratorio GNS3 es COMPARTIDO: solo se tocan los objetos creados
      por este script, identificados por nombre exacto (lo-ssh-<N>) y por
      la etiqueta del comentario. Nunca se usa "remove [find]" sin filtro.
    - Un fallo en un equipo NO detiene el procesamiento de los demás.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import yaml

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
    )
except Exception:  # pragma: no cover - netmiko ausente
    ConnectHandler = None  # type: ignore[assignment]
    NetmikoTimeoutException = Exception  # type: ignore[assignment]
    NetmikoAuthenticationException = Exception  # type: ignore[assignment]

# EXTRA (+10): el MikroTik también se puede consultar por su API REST (/rest,
# JSON sobre HTTPS). Necesita 'requests'; si falta, solo fallan los equipos REST.
try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:  # pragma: no cover - requests ausente
    requests = None  # type: ignore[assignment]
    InsecureRequestWarning = Exception  # type: ignore[assignment]


BASE = Path(__file__).resolve().parent
LOG_DIR = BASE / "logs"
REPORTE_JSON = BASE / "reporte_estado.json"

# Etiqueta de identificación de los objetos creados por ESTE laboratorio.
ETIQUETA = "LAB1-ITIEL13"

ROLES_VALIDOS = ("lectura", "escritura")

# device_type que NO usan Netmiko/SSH sino la API REST de RouterOS.
REST_TYPES = ("mikrotik_rest",)


# ---------------------------------------------------------------------------
# R4: comandos y parsers por device_type (agregar un fabricante = una entrada)
# ---------------------------------------------------------------------------
COMMANDS: dict[str, dict[str, Any]] = {
    "mikrotik_routeros": {
        "enable": False,
        "comandos": {
            "hostname": "/system identity print",
            "uptime": "/system resource print",
            "interfaces": "/ip address print terse",
            "default_route": "/ip route print terse where dst-address=0.0.0.0/0",
        },
    },
    "cisco_ios": {
        "enable": True,  # lab-ssh entra con privilegio 1; show run pide enable
        "comandos": {
            "hostname": "show running-config | include hostname",
            "uptime": "show version | include uptime",
            "interfaces": "show ip interface brief",
            "default_route": "show ip route 0.0.0.0",
        },
    },
    # EXTRA: mismo MikroTik, pero por su API REST (rutas del recurso /rest).
    "mikrotik_rest": {
        "enable": False,
        "comandos": {
            "hostname": "/rest/system/identity",
            "uptime": "/rest/system/resource",
            "interfaces": "/rest/ip/address",
            "default_route": "/rest/ip/route?dst-address=0.0.0.0/0",
        },
    },
}


# ---------------------------------------------------------------------------
# Parsers: reciben texto, devuelven dict/list. Nunca tiran el script abajo.
# ---------------------------------------------------------------------------
def texto_a_dict(linea: str) -> dict[str, str]:
    """'name: mt-lab' -> {'name': 'mt-lab'}. Si no hay ':', devuelve {}."""
    if ":" not in linea:
        return {}
    clave, valor = linea.split(":", 1)
    clave, valor = clave.strip(), valor.strip()
    return {clave: valor} if clave else {}


def parsear_terse(texto: str) -> list[dict[str, str]]:
    """Salida 'print terse' de RouterOS: una línea por registro con clave=valor."""
    filas: list[dict[str, str]] = []
    for linea in (texto or "").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("*"):
            continue
        registro: dict[str, str] = {}
        for token in linea.split():
            if "=" in token:
                clave, valor = token.split("=", 1)
                registro[clave] = valor
        if registro:
            filas.append(registro)
    return filas


def parse_mikrotik_identity(texto: str) -> dict[str, str]:
    """/system identity print -> {'name': 'mt-lab'}."""
    lineas = (texto or "").splitlines()
    for i, linea in enumerate(lineas):
        datos = texto_a_dict(linea)
        if "name" in datos:
            valor = datos["name"]
            # RouterOS puede partir un nombre largo en varias líneas según el
            # ancho de la consola; se concatenan las líneas de continuación.
            for cont in lineas[i + 1:]:
                cont = cont.strip()
                if not cont or ":" in cont:
                    break
                valor += cont
            return {"name": valor}
    return {}


def parse_mikrotik_resource(texto: str) -> dict[str, str]:
    """/system resource print -> {'uptime': ..., 'version': ..., ...}."""
    recursos: dict[str, str] = {}
    for linea in (texto or "").splitlines():
        datos = texto_a_dict(linea)
        recursos.update(datos)
    claves = ("uptime", "version", "architecture-name", "cpu", "cpu-count", "free-memory", "total-memory")
    return {k: recursos[k] for k in claves if k in recursos}


def parse_mikrotik_addresses(texto: str) -> list[dict[str, str]]:
    """/ip address print terse -> [{'address': ..., 'interface': ...}, ...]."""
    direcciones = []
    for registro in parsear_terse(texto):
        if "address" in registro:
            direcciones.append(
                {
                    "address": registro.get("address", ""),
                    "interface": registro.get("interface", ""),
                    "network": registro.get("network", ""),
                    "comment": registro.get("comment", ""),
                }
            )
    return direcciones


def parse_mikrotik_default_route(texto: str) -> dict[str, Any]:
    """Ruta por defecto (terse) -> {'gateway': ..., 'distance': ...} o {}."""
    for linea in (texto or "").splitlines():
        if "dst-address=0.0.0.0/0" not in linea:
            continue
        registro = parsear_terse(linea)
        fila = registro[0] if registro else {}
        # Los flags van como token sin '=' al inicio (p. ej. "As" = activa/estática).
        flags = " ".join(t for t in linea.split() if "=" not in t)
        return {
            "gateway": fila.get("gateway", ""),
            "distance": fila.get("distance", ""),
            "status": fila.get("status", ""),
            "active": "A" in flags,
        }
    return {}


def parse_cisco_hostname(texto: str) -> dict[str, str]:
    """'hostname R2' -> {'hostname': 'R2'}."""
    for linea in (texto or "").splitlines():
        partes = linea.strip().split()
        if len(partes) >= 2 and partes[0] == "hostname":
            return {"hostname": partes[1]}
    return {}


def parse_cisco_uptime(texto: str) -> dict[str, str]:
    """'R2 uptime is 1 day, 2 hours, 3 minutes' -> {'uptime': '...'}."""
    for linea in (texto or "").splitlines():
        if "uptime is" in linea:
            return {"uptime": linea.split("uptime is", 1)[1].strip()}
    return {}


def parse_cisco_interfaces(texto: str) -> list[dict[str, str]]:
    """show ip interface brief -> [{'interface':..., 'ip':..., 'status':...}]."""
    interfaces: list[dict[str, str]] = []
    for linea in (texto or "").splitlines():
        partes = linea.split()
        # Línea de datos: Interface, IP, OK?, Method, Status, Protocol
        if len(partes) >= 6 and re.match(r"^\d+\.\d+\.\d+\.\d+$|unassigned", partes[1]):
            interfaces.append(
                {
                    "interface": partes[0],
                    "ip": partes[1],
                    "ok": partes[2],
                    "method": partes[3],
                    # Status puede ser "up" o "administratively down".
                    "status": " ".join(partes[4:-1]),
                    "protocol": partes[-1],
                }
            )
    return interfaces


def parse_cisco_default_route(texto: str) -> dict[str, Any]:
    """show ip route 0.0.0.0 -> {'gateway': ..., 'network': ...} o {}."""
    gateway = ""
    red = ""
    for linea in (texto or "").splitlines():
        if "Gateway of last resort is" in linea:
            match = re.search(r"is (\S+) to network", linea)
            if match:
                gateway = match.group(1)
        match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", linea)
        if match and not gateway:
            gateway = match.group(1)
        # Algunos IOS muestran el next-hop como "* 10.60.30.1" (sin "via")
        # cuando se consulta una ruta puntual: show ip route 0.0.0.0.
        match = re.search(r"^\s*\*\s+(\d+\.\d+\.\d+\.\d+)", linea)
        if match and not gateway:
            gateway = match.group(1)
        match = re.search(r"0\.0\.0\.0/0", linea)
        if match:
            red = "0.0.0.0/0"
    return {"gateway": gateway, "network": red} if gateway or red else {}


# --- Parsers de la API REST: reciben JSON ya decodificado (dict/list) --------
def parse_rest_identity(datos: Any) -> dict[str, str]:
    """/rest/system/identity -> {'name': 'CHR'}."""
    return {"name": str(datos.get("name", ""))} if isinstance(datos, dict) else {}


def parse_rest_resource(datos: Any) -> dict[str, str]:
    """/rest/system/resource -> {'uptime': ..., 'version': ..., ...}."""
    if not isinstance(datos, dict):
        return {}
    claves = ("uptime", "version", "architecture-name", "cpu", "cpu-count", "free-memory", "total-memory")
    return {k: datos[k] for k in claves if k in datos}


def parse_rest_addresses(datos: Any) -> list[dict[str, str]]:
    """/rest/ip/address -> [{'address': ..., 'interface': ...}, ...]."""
    if not isinstance(datos, list):
        return []
    direcciones = []
    for registro in datos:
        if isinstance(registro, dict) and "address" in registro:
            direcciones.append(
                {
                    "address": registro.get("address", ""),
                    "interface": registro.get("interface", ""),
                    "network": registro.get("network", ""),
                    "comment": registro.get("comment", ""),
                }
            )
    return direcciones


def parse_rest_default_route(datos: Any) -> dict[str, Any]:
    """/rest/ip/route?dst-address=0.0.0.0/0 -> {'gateway': ..., 'active': ...}."""
    if not isinstance(datos, list):
        return {}
    for registro in datos:
        if isinstance(registro, dict) and registro.get("dst-address") == "0.0.0.0/0":
            return {
                "gateway": registro.get("gateway", ""),
                "distance": registro.get("distance", ""),
                "active": str(registro.get("active", "")).lower() == "true",
            }
    return {}


PARSERS: dict[str, dict[str, Callable[[str], Any]]] = {
    "mikrotik_routeros": {
        "hostname": parse_mikrotik_identity,
        "uptime": parse_mikrotik_resource,
        "interfaces": parse_mikrotik_addresses,
        "default_route": parse_mikrotik_default_route,
    },
    "cisco_ios": {
        "hostname": parse_cisco_hostname,
        "uptime": parse_cisco_uptime,
        "interfaces": parse_cisco_interfaces,
        "default_route": parse_cisco_default_route,
    },
    # EXTRA: los parsers REST reciben el JSON ya decodificado, no texto.
    "mikrotik_rest": {
        "hostname": parse_rest_identity,
        "uptime": parse_rest_resource,
        "interfaces": parse_rest_addresses,
        "default_route": parse_rest_default_route,
    },
}


# ---------------------------------------------------------------------------
# R1: inventario
# ---------------------------------------------------------------------------
def cargar_inventario(ruta: Path) -> list[dict[str, Any]]:
    """Lee el YAML y devuelve la lista de equipos."""
    with ruta.open("r", encoding="utf-8") as archivo:
        datos = yaml.safe_load(archivo)
    if not isinstance(datos, dict) or "equipos" not in datos:
        raise ValueError(f"{ruta}: se esperaba un diccionario con la clave 'equipos'")
    equipos = datos["equipos"]
    if not isinstance(equipos, list) or not equipos:
        raise ValueError(f"{ruta}: 'equipos' debe ser una lista no vacía")
    return equipos


def validar_inventario(equipos: list[dict[str, Any]]) -> None:
    """Falla temprano si falta algún campo o el device_type no está soportado."""
    obligatorios = ("nombre", "host", "device_type", "usuario", "rol")
    vistos: set[str] = set()
    for equipo in equipos:
        faltantes = [campo for campo in obligatorios if not equipo.get(campo)]
        if faltantes:
            raise ValueError(f"Equipo {equipo.get('nombre', '?')}: faltan campos {faltantes}")
        if equipo["rol"] not in ROLES_VALIDOS:
            raise ValueError(
                f"Equipo {equipo['nombre']}: rol '{equipo['rol']}' inválido "
                f"(use uno de {ROLES_VALIDOS})"
            )
        if equipo["device_type"] not in COMMANDS:
            raise ValueError(
                f"Equipo {equipo['nombre']}: device_type '{equipo['device_type']}' "
                f"no soportado (disponibles: {', '.join(COMMANDS)})"
            )
        if equipo["nombre"] in vistos:
            raise ValueError(f"Nombre duplicado en el inventario: {equipo['nombre']}")
        vistos.add(equipo["nombre"])


# ---------------------------------------------------------------------------
# R2: credenciales seguras
# ---------------------------------------------------------------------------
def variable_password(nombre: str) -> str:
    """'mt-lab' -> 'LAB_PASS_MT_LAB' (guiones como guiones bajos, en mayúsculas)."""
    return "LAB_PASS_" + nombre.upper().replace("-", "_")


def obtener_credencial(nombre: str) -> str:
    """Lee LAB_PASS_<NOMBRE> del entorno; si no existe, la pide con getpass.

    Nunca usa input() para la contraseña ni la imprime ni la guarda.
    """
    variable = variable_password(nombre)
    password = os.getenv(variable)
    if password:
        return password
    if not sys.stdin.isatty():
        raise RuntimeError(
            f"No hay TTY para pedir la contraseña de '{nombre}'. "
            f"Defina la variable de entorno {variable}."
        )
    return getpass.getpass(f"Contraseña de {nombre} ({variable}): ")


# ---------------------------------------------------------------------------
# R3: conexión robusta
# ---------------------------------------------------------------------------
def parametros_conexion(equipo: dict[str, Any], password: str, log_path: Path) -> dict[str, Any]:
    """Arma el diccionario que espera ConnectHandler (sin secretos en disco)."""
    return {
        "device_type": equipo["device_type"],
        "host": equipo["host"],
        "port": int(equipo.get("port", 22)),
        "username": equipo["usuario"],
        "password": password,
        "conn_timeout": int(equipo.get("conn_timeout", 20)),
        "fast_cli": False,
        "session_log": str(log_path),
    }


def conectar_equipo(params: dict[str, Any], requiere_enable: bool) -> Any:
    """Abre la sesión SSH. El caller la cierra con 'with' (ver procesar_equipo)."""
    conn = ConnectHandler(**params)
    if requiere_enable:
        # En IOS, 'show running-config' exige modo privilegiado.
        conn.enable()
    return conn


class RouterOSRest:
    """Cliente mínimo de la API REST de RouterOS (/rest, JSON sobre HTTPS).

    EXTRA (+10): permite consultar el mismo MikroTik por REST en vez de SSH.
    El certificado del laboratorio es autofirmado, así que se desactiva la
    verificación TLS (verify=False); la advertencia de urllib3 ya se silenció.
    Escribe en logs/<nombre>.log para que cada equipo tenga su session_log.
    """

    def __init__(
        self,
        host: str,
        port: int,
        usuario: str,
        password: str,
        log_path: Path | None = None,
        timeout: int = 20,
    ) -> None:
        if requests is None:
            raise RuntimeError("Falta 'requests' (pip install -r requirements.txt)")
        self.base = f"https://{host}:{int(port)}"
        self.timeout = int(timeout)
        self.log_path = log_path
        self.sesion = requests.Session()
        self.sesion.auth = (usuario, password)
        self.sesion.verify = False  # certificado autofirmado del laboratorio
        self.sesion.headers.update({"Accept": "application/json"})

    def _registrar(self, texto: str) -> None:
        if not self.log_path:
            return
        with self.log_path.open("a", encoding="utf-8") as archivo:
            archivo.write(texto + "\n")

    def get(self, ruta: str) -> Any:
        """GET a un recurso /rest y devuelve el JSON ya decodificado."""
        self._registrar(f"GET {ruta}")
        respuesta = self.sesion.get(f"{self.base}{ruta}", timeout=self.timeout)
        respuesta.raise_for_status()
        self._registrar(respuesta.text)
        return respuesta.json()

    def disconnect(self) -> None:
        self.sesion.close()


# ---------------------------------------------------------------------------
# R4: recolección de estado
# ---------------------------------------------------------------------------
def recolectar_estado(conn: Any, device_type: str) -> dict[str, Any]:
    """Ejecuta los comandos del device_type y devuelve datos ya parseados.

    Sirve para SSH (conn.send_command -> texto) y para la API REST
    (conn.get -> JSON); cada parser recibe lo que devuelva el transporte.
    """
    ficha = COMMANDS[device_type]
    parsers = PARSERS[device_type]
    es_rest = device_type in REST_TYPES
    datos: dict[str, Any] = {}
    for clave, objetivo in ficha["comandos"].items():
        try:
            crudo = conn.get(objetivo) if es_rest else conn.send_command(objetivo)
            datos[clave] = parsers[clave](crudo)
        except Exception as error:  # un parser roto no derriba el inventario
            datos[clave] = None
            datos[f"{clave}_error"] = f"{type(error).__name__}: {error}"
    return datos


# ---------------------------------------------------------------------------
# R5: reporte y tabla
# ---------------------------------------------------------------------------
def gateway_de(datos: dict[str, Any]) -> str:
    """Extrae el gateway por defecto para la tabla resumen."""
    ruta = datos.get("default_route") or {}
    if isinstance(ruta, dict):
        return ruta.get("gateway") or "-"
    return "-"


def interfaces_de(datos: dict[str, Any]) -> int:
    lista = datos.get("interfaces")
    return len(lista) if isinstance(lista, list) else 0


def hostname_de(datos: dict[str, Any]) -> str:
    for clave in ("hostname", "name"):
        valor = datos.get(clave)
        if isinstance(valor, dict):
            return valor.get(clave) or valor.get("name") or "-"
        if isinstance(valor, str):
            return valor
    return "-"


def generar_reporte(resultados: list[dict[str, Any]], ruta: Path = REPORTE_JSON) -> None:
    """Escribe reporte_estado.json (sin contraseñas: nunca se serializan)."""
    with ruta.open("w", encoding="utf-8") as archivo:
        json.dump(resultados, archivo, indent=2, ensure_ascii=False)
        archivo.write("\n")
    print(f"[OK] Reporte escrito en {ruta}")


def mostrar_resumen(resultados: list[dict[str, Any]]) -> None:
    """Tabla: Equipo | IP | Estado | Interfaces | Gateway."""
    filas = []
    for resultado in resultados:
        datos = resultado.get("datos") or {}
        if resultado["estado"] == "ok":
            filas.append(
                (
                    resultado["nombre"],
                    resultado["host"],
                    "OK",
                    str(interfaces_de(datos)),
                    gateway_de(datos),
                )
            )
        else:
            filas.append((resultado["nombre"], resultado["host"], "ERROR", "-", "-"))

    encabezados = ("Equipo", "IP", "Estado", "Interfaces", "Gateway")
    ancho = [max(len(encabezados[i]), *(len(f[i]) for f in filas)) for i in range(5)]
    linea = "  ".join("-" * a for a in ancho)
    print()
    print("  ".join(h.ljust(ancho[i]) for i, h in enumerate(encabezados)))
    print(linea)
    for fila in filas:
        print("  ".join(valor.ljust(ancho[i]) for i, valor in enumerate(fila)))
    print()

    for resultado in resultados:
        if resultado["estado"] != "ok":
            print(f"  {resultado['nombre']} ({resultado['host']}): {resultado.get('mensaje', '')}")


def registrar_error(
    resultados: list[dict[str, Any]], equipo: dict[str, Any], mensaje: str
) -> None:
    """Añade un equipo al reporte con estado=error (sin credenciales)."""
    resultados.append(
        {
            "nombre": equipo["nombre"],
            "host": equipo["host"],
            "device_type": equipo["device_type"],
            "rol": equipo.get("rol", ""),
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "estado": "error",
            "mensaje": mensaje,
            "datos": {},
        }
    )
    print(f"[ERROR] {equipo['nombre']} ({equipo['host']}): {mensaje}", file=sys.stderr)


# ---------------------------------------------------------------------------
# R6: configuración idempotente del MikroTik (solo rol=escritura)
# ---------------------------------------------------------------------------
def resolver_n(valor_cli: str | None) -> int:
    """Número de lista N: --n o LAB_N. Si no existe, no se inventa ninguno."""
    bruto = valor_cli or os.getenv("LAB_N")
    if not bruto:
        raise ValueError(
            "Falta el número de lista N. Use --n <numero> o exporte LAB_N=<numero>."
        )
    try:
        n = int(bruto)
    except ValueError as error:
        raise ValueError(f"N inválido: '{bruto}' (debe ser un número entero)") from error
    if not 1 <= n <= 254:
        raise ValueError(f"N inválido: {n} (debe estar entre 1 y 254)")
    return n


def _mt_len(conn: Any, find: str) -> int:
    """Cuenta objetos: :put [:len [/algo find ...]] -> '0' = no existe."""
    salida = conn.send_command(f":put [:len [{find}]]").strip()
    return int(salida) if salida.isdigit() else 0


def objetivos_mikrotik(n: int) -> dict[str, str]:
    """Los tres objetos que este laboratorio asegura en el MikroTik."""
    return {
        "bridge": f"lo-ssh-{n}",
        "ip": f"10.253.0.{n}/32",
        "comment": f"{ETIQUETA} N={n}",
    }


def aplicar_configuracion_mikrotik(conn: Any, n: int) -> list[str]:
    """Consultar -> actuar -> verificar. Devuelve la lista de cambios aplicados."""
    objetivo = objetivos_mikrotik(n)
    cambios: list[str] = []

    # 1) Bridge lo-ssh-<N> SIN puertos físicos (nunca se agregan puertos).
    existe_bridge = _mt_len(
        conn, f'/interface bridge find name="{objetivo["bridge"]}"'
    )
    if existe_bridge == 0:
        conn.send_config_set(
            [
                f'/interface bridge add name={objetivo["bridge"]} '
                f'comment="{objetivo["comment"]}"'
            ]
        )
        cambios.append(f"bridge {objetivo['bridge']} creado")
    else:
        # Solo se corrige el comentario si el nombre coincide exactamente
        # con el nuestro: es imposible que sea de otro estudiante.
        comentario = conn.send_command(
            f'/interface bridge print detail where name="{objetivo["bridge"]}"'
        )
        if objetivo["comment"] not in comentario:
            conn.send_config_set(
                [
                    f'/interface bridge set [find name="{objetivo["bridge"]}"] '
                    f'comment="{objetivo["comment"]}"'
                ]
            )
            cambios.append(f"comentario del bridge {objetivo['bridge']} corregido")

    # 2) IP 10.253.0.<N>/32 sobre esa interfaz.
    existe_ip = _mt_len(
        conn, f'/ip address find address="{objetivo["ip"]}" interface="{objetivo["bridge"]}"'
    )
    if existe_ip == 0:
        # Si la IP existe sobre OTRA interfaz no se toca (podría ser ajena).
        ip_en_otra = _mt_len(conn, f'/ip address find address="{objetivo["ip"]}"')
        if ip_en_otra:
            raise RuntimeError(
                f"La IP {objetivo['ip']} ya existe en otra interfaz; "
                "no se modifica nada ajeno. Revise --estado y limpie a mano."
            )
        conn.send_config_set(
            [
                f'/ip address add address={objetivo["ip"]} '
                f'interface={objetivo["bridge"]} comment="{objetivo["comment"]}"'
            ]
        )
        cambios.append(f"IP {objetivo['ip']} sobre {objetivo['bridge']} creada")

    return cambios


def verificar_configuracion(conn: Any, n: int) -> bool:
    """Lee después de escribir: confirma que el bridge y la IP existen."""
    objetivo = objetivos_mikrotik(n)
    bridge_ok = _mt_len(
        conn, f'/interface bridge find name="{objetivo["bridge"]}"'
    ) == 1
    ip_ok = _mt_len(
        conn, f'/ip address find address="{objetivo["ip"]}" interface="{objetivo["bridge"]}"'
    ) == 1
    return bridge_ok and ip_ok


def limpiar_configuracion(conn: Any, n: int) -> list[str]:
    """Elimina SOLO los objetos de este estudiante (nombre exacto + IP exacta)."""
    objetivo = objetivos_mikrotik(n)
    cambios: list[str] = []
    if _mt_len(conn, f'/ip address find address="{objetivo["ip"]}"'):
        conn.send_config_set(
            [f'/ip address remove [find address="{objetivo["ip"]}"]']
        )
        cambios.append(f"IP {objetivo['ip']} eliminada")
    if _mt_len(conn, f'/interface bridge find name="{objetivo["bridge"]}"'):
        conn.send_config_set(
            [f'/interface bridge remove [find name="{objetivo["bridge"]}"]']
        )
        cambios.append(f"bridge {objetivo['bridge']} eliminado")
    return cambios


# ---------------------------------------------------------------------------
# Procesamiento por equipo (un fallo NO detiene a los demás)
# ---------------------------------------------------------------------------
def procesar_equipo(
    equipo: dict[str, Any],
    args: argparse.Namespace,
) -> dict[str, Any]:
    """Conecta, recolecta y (según modo/rol) configura o limpia UN equipo."""
    device_type = equipo["device_type"]
    ficha = COMMANDS[device_type]
    LOG_DIR.mkdir(exist_ok=True)
    log_path = LOG_DIR / f"{equipo['nombre']}.log"

    # Un equipo REST puede reutilizar la credencial de otro (campo 'credencial'
    # del YAML) para no duplicar el secreto ni una variable de entorno.
    password = obtener_credencial(equipo.get("credencial") or equipo["nombre"])

    resultado: dict[str, Any] = {
        "nombre": equipo["nombre"],
        "host": equipo["host"],
        "device_type": device_type,
        "rol": equipo.get("rol", ""),
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "estado": "ok",
        "datos": {},
    }

    conn = None
    try:
        if device_type in REST_TYPES:
            conn = RouterOSRest(
                equipo["host"],
                equipo.get("port", 443),
                equipo["usuario"],
                password,
                log_path=log_path,
                timeout=int(equipo.get("conn_timeout", 20)),
            )
        else:
            params = parametros_conexion(equipo, password, log_path)
            conn = conectar_equipo(params, ficha["enable"])

        if args.estado:
            resultado["datos"] = recolectar_estado(conn, device_type)
            print(f"[OK] {equipo['nombre']}: estado recolectado (sin cambios)")
            return resultado

        if args.limpiar:
            if equipo["rol"] != "escritura":
                print(f"[=] {equipo['nombre']}: rol lectura, nada que limpiar")
                return resultado
            resultado["cambios"] = limpiar_configuracion(conn, args.n_numero)
            print(f"[OK] {equipo['nombre']}: limpieza aplicada ({len(resultado['cambios'])} objetos)")
            return resultado

        # Modo normal: recolectar estado de TODOS y configurar solo rol=escritura.
        resultado["datos"] = recolectar_estado(conn, device_type)

        if equipo["rol"] == "escritura":
            cambios = aplicar_configuracion_mikrotik(conn, args.n_numero)
            verificado = verificar_configuracion(conn, args.n_numero)
            resultado["cambios"] = cambios
            resultado["verificado"] = verificado
            if not verificado:
                raise RuntimeError("La verificación posterior al cambio falló")
            if cambios:
                print(f"[+] {equipo['nombre']}: cambios aplicados: {', '.join(cambios)}")
            else:
                print(f"[=] {equipo['nombre']}: sin cambios (ya estaba configurado)")
        else:
            print(f"[=] {equipo['nombre']}: rol lectura, no se modifica")

        return resultado
    finally:
        if conn is not None:
            conn.disconnect()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Laboratorio 1 ITIEL-13: inventario, estado y config segura (Netmiko)",
    )
    modo = parser.add_mutually_exclusive_group()
    modo.add_argument(
        "--estado",
        action="store_true",
        help="solo consulta y genera el reporte; NO modifica configuración",
    )
    modo.add_argument(
        "--limpiar",
        action="store_true",
        help="elimina SOLO los objetos creados por este laboratorio (MikroTik)",
    )
    parser.add_argument(
        "--n",
        dest="n",
        metavar="N",
        help="número de lista del estudiante (también: variable LAB_N)",
    )
    parser.add_argument(
        "--inventario",
        default=str(BASE / "inventario.yaml"),
        help="ruta del inventario YAML (por defecto: inventario.yaml)",
    )
    parser.add_argument(
        "--reporte",
        default=str(REPORTE_JSON),
        help="ruta del reporte JSON (por defecto: reporte_estado.json)",
    )
    args = parser.parse_args(argv)

    # N solo hace falta cuando se va a configurar o limpiar el MikroTik.
    if not args.estado:
        try:
            args.n_numero = resolver_n(args.n)
        except ValueError as error:
            parser.error(str(error))
    else:
        args.n_numero = None
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        equipos = cargar_inventario(Path(args.inventario))
        validar_inventario(equipos)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"ERROR de inventario: {error}", file=sys.stderr)
        return 1

    necesita_netmiko = any(e["device_type"] not in REST_TYPES for e in equipos)
    necesita_requests = any(e["device_type"] in REST_TYPES for e in equipos)
    if necesita_netmiko and ConnectHandler is None:
        print("ERROR: netmiko no está instalado (pip install -r requirements.txt)", file=sys.stderr)
        return 1
    if necesita_requests and requests is None:
        print("ERROR: 'requests' no está instalado (pip install -r requirements.txt)", file=sys.stderr)
        return 1

    print(f"Equipos en el inventario: {len(equipos)}"
          f" | modo: {'estado' if args.estado else 'limpiar' if args.limpiar else 'normal'}"
          f" | N={args.n_numero if args.n_numero is not None else '-'}")

    resultados: list[dict[str, Any]] = []
    for equipo in equipos:
        try:
            resultados.append(procesar_equipo(equipo, args))
        except NetmikoTimeoutException as error:
            registrar_error(resultados, equipo, f"timeout de conexión: {error}")
        except NetmikoAuthenticationException as error:
            registrar_error(resultados, equipo, f"autenticación fallida: {error}")
        except Exception as error:
            registrar_error(resultados, equipo, f"{type(error).__name__}: {error}")

    generar_reporte(resultados, Path(args.reporte))
    mostrar_resumen(resultados)

    fallas = sum(1 for r in resultados if r["estado"] != "ok")
    return 1 if fallas else 0


if __name__ == "__main__":
    sys.exit(main())
