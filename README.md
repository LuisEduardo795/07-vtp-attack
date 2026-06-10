# 07 — Ataque VTP (VLAN Trunking Protocol Attack)
Ataque VTP — agrega/borra VLANs


## Objetivo del Laboratorio
Demostrar cómo un atacante puede explotar el protocolo VTP para
agregar o eliminar VLANs en toda la red enviando mensajes VTP
con número de revisión alto, afectando la conectividad de todos
los dispositivos conectados.

---

## Objetivo del Script
Enviar mensajes VTP Summary y Subset Advertisement con número de
revisión elevado para que los switches adopten la base de datos
de VLANs del atacante.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red | Obligatorio |
| `--domain` | Nombre del dominio VTP | cisco |
| `--mode` | add=agregar, delete=borrar VLANs | add |
| `--vlans` | VLANs a agregar (separadas por coma) | 100,200,300 |
| `--revision` | Número de revisión (0=aleatorio alto) | 0 |
| `-c` | Veces a enviar los mensajes | 5 |
| `-d` | Delay entre envíos (seg) | 1.0 |

### Requisitos
- Python 3.8+
- Scapy: `pip3 install scapy`
- Puerto conectado a un trunk VTP
- Conocer el nombre del dominio VTP
- Ejecutar como root

---

## Topología de Red

```
[Ubuntu-Atacante]──e0/0──[SW-Core]──e0/1──[Linux-Victima]
 192.168.1.50                               192.168.1.10
```

| Dispositivo | Interfaz | IP |
|---|---|---|
| Ubuntu-Atacante | ens3 | 192.168.1.50/24 |
| SW-Core | e0/0 - e0/1 | — |
| Linux-Victima | ens3 | 192.168.1.10/24 |

---

## Funcionamiento del Script

1. Genera un número de revisión muy alto (mayor al del switch)
2. Envía VTP Summary Advertisement con ese número de revisión
3. El switch compara: si la revisión recibida > revisión actual → acepta
4. Envía VTP Subset Advertisement con la lista de VLANs falsas
5. El switch adopta la nueva base de datos de VLANs
6. En modo DELETE: envía lista vacía → borra todas las VLANs

---

## Uso

```bash
# Agregar VLANs falsas
sudo python3 vtp_attack.py -i ens3 --domain cisco --mode add --vlans 100,200,300

# Borrar todas las VLANs (muy destructivo)
sudo python3 vtp_attack.py -i ens3 --domain cisco --mode delete

# Verificar en el switch
show vlan brief
show vtp status
```

---

## Capturas de Pantalla

### Ataque en ejecución
![VTP ataque](capturas/vtp_ataque.png)

### VLANs modificadas en el switch
![VLANs modificadas](capturas/vtp_switch.png)

---

## Contramedidas

```cisco
! Cambiar a modo VTP Transparent (no acepta ni propaga VTP)
vtp mode transparent

! O cambiar a modo OFF (más seguro)
vtp mode off

! Configurar contraseña VTP (dificulta el ataque)
vtp password MiClaveSegura123

! Verificar
show vtp status
show vtp password
```

---

## Video Demostración
[![Video](https://img.shields.io/badge/YouTube-Ver%20Video-red)](URL_DEL_VIDEO)

---

## Referencias
- [Cisco VTP Documentation](https://www.cisco.com/c/en/us/support/docs/lan-switching/vtp/10558-21.html)
- [VTP Attack — SANS](https://www.sans.org)
