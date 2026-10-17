# Laboratorio 1 — Inventario, Estado y Configuración Segura con Python + SSH (Netmiko)

**Curso:** ITIEL-13 — Redes Programables (Grupo 01)  
**Profesor:** Randall Zamora Rojas  
**Periodo:** III-2026  
**Estudiante:** Rafa Antonio (repositorio `Laboratorio_1_Rafa_Antonio`)

---

## 1. Objetivo

Integrar Linux, venv, SSH y Netmiko en un script que:

1. Lea un inventario en YAML con los equipos del laboratorio GNS3 (**sin contraseñas**).
2. Se conecte por SSH con Netmiko y recolecte el estado como **datos estructurados (JSON)**.
3. Aplique en el MikroTik un cambio de configuración **sin duplicar nada**: correr el script dos veces deja el equipo igual (idempotencia).

`rutas_estaticas.py` complementa el laboratorio con la conectividad PC1 ↔ PC2 a través del Cisco y el MikroTik.

## 2. Topología

```
                    INTERNET
                       |
                    SW1 / LAN 10.60.30.0/24  (gateway .1)
                   /                          \
     MikroTik RouterOS v7                 Cisco IOS 3725
     10.60.30.202 (ether1)                10.60.30.203 (Fa0/0)
     rol: escritura                        rol: lectura
     usuario: lab-ssh                      usuario: lab-ssh
          |                                     |
     PC2 (172.16.20.0/24, gw .1)          PC1 (172.16.10.0/24, gw .1)
```

El equipo Linux donde corre el script está **fuera** de GNS3 y accede al laboratorio por Tailscale.

Los equipos del GNS3 son **compartidos**: todo lo creado por este proyecto lleva la etiqueta `LAB1-ITIEL13` y el nombre exacto `lo-ssh-<N>`, donde `<N>` es el número de lista del estudiante.

## 3. Requisitos

- Linux, WSL o VM con Python 3.10+.
- Acceso SSH al laboratorio (Tailscale activo hacia la red 10.60.30.0/24).
- Usuario `lab-ssh` y su clave (entregada en clase).
- Git (opcional pero recomendado).

## 4. Instalación

```bash
git clone https://github.com/RafitaUTN/Laboratorio_1_Rafa_Antonio.git
cd Laboratorio_1_Rafa_Antonio

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 5. Inventario

`inventario.yaml` define los equipos **fuera del código**:

```yaml
equipos:
  - nombre: mt-lab
    host: 10.60.30.202
    port: 22
    device_type: mikrotik_routeros
    usuario: lab-ssh
    rol: escritura
  - nombre: cisco-lab
    host: 10.60.30.203
    port: 22
    device_type: cisco_ios
    usuario: lab-ssh
    rol: lectura
```

**Nunca** se incluye `password:`, `secret:` ni nada similar. Agregar otro fabricante = agregar otra entrada con su `device_type` y sus comandos en el diccionario `COMMANDS` de `lab1_inventario.py`.

## 6. Variables de entorno

La contraseña de cada equipo se lee de `LAB_PASS_<NOMBRE>` (nombre en mayúsculas, guiones como `_`). Si la variable no existe, el script la pide con `getpass` (sin eco, sin `input()`).

```bash
export LAB_PASS_MT_LAB='...'
export LAB_PASS_CISCO_LAB='...'
```

Opcional (solo para `rutas_estaticas.py`, si el enable secret difiere de la clave SSH):

```bash
export LAB_SECRET_CISCO_LAB='...'
```

Número de lista (obligatorio para configurar/limpiar el MikroTik):

```bash
export LAB_N=5      # <- ponga SU número de lista
```

> Los valores reales de las contraseñas **nunca** se escriben en este archivo, en el YAML, en el código ni en el repositorio.

## 7. Ejecución

Defina primero su número de lista (una sola forma, elija una):

```bash
export LAB_N=5            # o pase --n 5 en cada ejecución
```

### 7.1 Solo estado (antes de tocar nada)

```bash
python lab1_inventario.py --estado
```

Conecta, consulta, genera `reporte_estado.json` y muestra la tabla. **No modifica nada.**

### 7.2 Estado + configuración idempotente (MikroTik)

```bash
python lab1_inventario.py
```

1. Carga y valida el inventario.
2. Pide las credenciales (entorno o `getpass`).
3. Conecta a cada equipo (un fallo no detiene el resto).
4. Recolecta y parsea el estado.
5. Solo en `rol: escritura` (MikroTik) asegura: bridge `lo-ssh-<N>` sin puertos, IP `10.253.0.<N>/32` y comentario `LAB1-ITIEL13 N=<N>`.
6. Verifica con un comando de lectura.
7. Genera el reporte y la tabla.

**Segunda ejecución:** debe informar `sin cambios (ya estaba configurado)` y no debe crear nada duplicado.

### 7.3 Limpieza (solo objetos propios)

```bash
python lab1_inventario.py --limpiar
```

Elimina **únicamente** el bridge `lo-ssh-<N>` y la IP `10.253.0.<N>/32` de este estudiante. Nunca usa `remove [find]` sin filtro exacto; no toca objetos de otros estudiantes ni el resto de la configuración.

`--estado` y `--limpiar` son mutuamente excluyentes.

### 7.4 Manejo de errores

Para probar el manejo de errores **sin tocar el inventario**:

```bash
LAB_PASS_MT_LAB=incorrecta python lab1_inventario.py --estado
```

El script registra el error de autenticación de ese equipo, continúa con los demás, genera el reporte y sale con código 1.

## 8. Rutas estáticas (PC1 ↔ PC2)

`rutas_estaticas.py` resuelve: cada router solo conoce su LAN, así que el ping entre PC1 y PC2 se pierde en el gateway 10.60.30.1.

- **MikroTik:** ruta `172.16.10.0/24` vía `10.60.30.203` + excepción de NAT (`accept` antes del masquerade).
- **Cisco:** ruta `172.16.20.0/24` vía `10.60.30.202` + ACL extendida `NAT-PC1` que excluye el tráfico entre las dos LAN del NAT de Internet.

```bash
python rutas_estaticas.py --estado    # antes: muestra NO aplicado
python rutas_estaticas.py             # aplica + ping router a router
python rutas_estaticas.py             # 2.ª vez: sin cambios (idempotente)
python rutas_estaticas.py --limpiar   # vuelve al estado inicial
```

Pruebas desde GNS3:

```
PC1> ping 172.16.20.1      # gateway de PC2
PC1> ping 172.16.20.100    # PC2 (si su IP es otra, use la real)
PC2> ping 172.16.10.1      # gateway de PC1
PC2> ping 172.16.10.11     # PC1 (si su IP es otra, use la real)
```

## 9. Reporte y logs

- `reporte_estado.json`: lista de equipos con `nombre`, `host`, `device_type`, `rol`, `timestamp`, `estado` (`ok`/`error`) y `datos` ya parseados (hostname, uptime, interfaces, ruta por defecto).
- `logs/mt-lab.log` y `logs/cisco-lab.log`: `session_log` de Netmiko, uno por equipo (excluidos del repositorio por `.gitignore`).

## 10. Estructura del proyecto

```
Laboratorio_1_Rafa_Antonio/
├── README.md              # este archivo
├── requirements.txt       # netmiko, pyyaml
├── .gitignore
├── inventario.yaml        # SIN contraseñas
├── lab1_inventario.py     # script principal (R1–R6)
├── rutas_estaticas.py     # conectividad PC1 ↔ PC2
├── reporte_estado.json    # salida de una ejecución real (se genera)
└── logs/                  # session_log de cada equipo (generados)
```

## 11. Seguridad

- Cero contraseñas en código, YAML, JSON, README, logs o Git.
- Contraseñas solo por variable de entorno o `getpass` (nunca `input()`).
- `ConnectHandler` siempre dentro de un bloque `with`.
- Manejo de `NetmikoTimeoutException`, `NetmikoAuthenticationException` y `Exception` **por equipo**: un fallo no detiene el resto.
- Configuración solo en equipos con `rol: escritura`; el Cisco se consulta pero no se modifica desde `lab1_inventario.py`.
- Limpieza y configuración siempre con filtros exactos (nombre/etiqueta propios); jamás `remove [find]` global, jamás reset de configuración.

## 12. Idempotencia

Todo sigue el patrón **consultar → actuar → verificar**:

1. Consultar si el objeto existe (`:put [:len [/interface bridge find name="lo-ssh-<N>"]]`).
2. Si existe: no crear otro; solo corregir el comentario si falta.
3. Si no existe: crear.
4. Verificar con un comando de lectura después del cambio.

Por eso la segunda ejecución informa **sin cambios**.

## 13. Declaración de uso de IA

> Se utilizó asistencia de inteligencia artificial como apoyo para revisar la estructura del código, proponer funciones, mejorar el manejo de errores, documentación y pruebas. La configuración de la topología, las credenciales, la validación de conectividad y la ejecución final fueron realizadas y verificadas por el estudiante.

## 14. Licencia / uso

Código con fines académicos del curso ITIEL-13. El laboratorio GNS3 es compartido: ejecute siempre `--estado` antes de `--limpiar` y no modifique objetos que no lleven su etiqueta.
